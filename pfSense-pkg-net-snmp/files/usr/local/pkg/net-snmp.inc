<?php

/*
 * net-snmp.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2017 Rubicon Communications, LLC (Netgate)
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once("globals.inc");
require_once("services.inc");
require_once("service-utils.inc");
require_once("pfsense-utils.inc");

global $snmpd_config_file;
$snmpd_config_file = "/var/etc/netsnmpd.conf";
global $snmpd_users_file;
$snmpd_users_file = "/var/etc/netsnmpd-users.conf";
global $snmptrapd_config_file;
$snmptrapd_config_file = "/var/etc/netsnmptrapd.conf";

function netsnmp_install_command() {
	global $config;
	/* Make some default settings/entries/users */
}

/* Get a list of CA Certificates for use with trustCert */
function netsnmp_get_ca_certs() {
	global $config;
	$ca_arr = array();
	$ca_arr[] = array('refid' => 'none', 'descr' => 'None');
	$ca_arr[] = array('refid' => 'self', 'descr' => 'Self-Signed Certificate');

	if (is_array($config['ca'])) {
		foreach ($config['ca'] as $ca) {
			$ca_arr[] = array('refid' => $ca['refid'], 'descr' => $ca['descr']);
		}
	}
	return $ca_arr;
}

/* Get a list of server certificates for use with localCert */
function netsnmp_get_server_certs() {
	global $config;
	$cert_arr = array();
	$cert_arr[] = array('refid' => 'none', 'descr' => 'None');

	if (is_array($config['cert'])) {
		foreach ($config['cert'] as $cert) {
			$cert_arr[] = array('refid' => $cert['refid'], 'descr' => $cert['descr']);
		}
	}
	return $cert_arr;
}

/* Get a list of SNMPv3 User names */
function netsnmp_get_usernames() {
	global $config;
	$users = &$config['installedpackages']['netsnmpusers']['config'];
	$usernames = array();

	if (is_array($users)) {
		foreach ($users as $user) {
			/* We are only interested in the names */
			$usernames[] = array('refid' => $user['username'], 'descr' => $user['username']);
		}
	}
	return $usernames;
}

/* Write snmpd config file */
function netsnmp_resync() {
	global $config, $snmpd_config_file, $snmpd_users_file;

	/* Global Settings tab */
	$nsettings = &$config['installedpackages']['netsnmp']['config'][0];

	/* If the service isn't enabled, nothing to do. Stop the service and return. */
	if ($nsettings['enable_snmpd'] != "on") {
		stop_service('net-snmpd');
		return;
	}

	$snmpd_config = "";

	/* The binding / agent addresses control where and how snmpd listens for incoming connections. */
	$agentaddresses = array();
	if (is_array($nsettings['row'])) {
		foreach ($nsettings['row'] as $agent) {
			$aa = "";
			/* At a minimum, a port must be supplied. UDP is assumed in that case */
			if (!empty($agent['snmpport'])) {
				$aa = $agent['snmpport'];
			}
			/* An address or hostname is optional but needs to be before the port */
			if (!empty($agent['ipaddress'])) {
				$aa = "{$agent['ipaddress']}:{$aa}";
			}
			/* Transport is optional (UDP is assumed) */
			if (!empty($agent['transport'])) {
				$aa = "{$agent['transport']}:{$aa}";
			}
			/* Only keep this entry if it contains data */
			if (!empty($aa)) {
				$agentaddresses[] = $aa;
			}
		}
	}

	/* Agent address list is comma-separated, no spaces: a:b:c,d:e:f,g:h:i */
	if (!empty($agentaddresses)) {
		$snmpd_config .= "agentaddress " . implode(',', $agentaddresses) . "\n";
	}

	/* If a manual string engine ID type is set, use the specified string, otherwise use the type directly. */
	if (($nsettings['engineidtype'] != 'string') && !empty($nsettings['engineidtype'])) {
		$snmpd_config .= "engineIDType {$nsettings['engineidtype']}\n";
	} elseif (($nsettings['engineidtype'] == 'string') && !empty($nsettings['engineid'])) {
		$snmpd_config .= "engineID {$nsettings['engineid']}\n";
	}

	if ($nsettings['usetransportprefix'] == "on") {
		$snmpd_config .= "[snmp] tsmUseTransportPrefix yes\n";
	} else {
		$snmpd_config .= "[snmp] tsmUseTransportPrefix no\n";
	}

	if (!empty($nsettings['maxgetbulkrepeats'])) {
		$snmpd_config .= "maxGetbulkRepeats {$nsettings['maxgetbulkrepeats']}\n";
	}
	if (!empty($nsettings['maxgetbulkresponses'])) {
		$snmpd_config .= "maxGetbulkResponses {$nsettings['maxgetbulkresponses']}\n";
	}

	/* Dump custom options into the configuration as-is */
	if (!empty($nsettings['custom_options'])) {
		$snmpd_config .= "{$nsettings['custom_options']}\n";
	}

/*
	TODO: Implement certificate backend, see
	http://www.net-snmp.org/wiki/index.php/Using_DTLS

	/var/net-snmp/cert_indexes

	[snmp] localCert <specifier>
	[snmp] trustCert <specifier>

	<ca_cert>5841c3857bea2</ca_cert>
	<server_cert>5841c3c235ab0</server_cert>
*/

	/* Host Information tab */
	$nhisettings = &$config['installedpackages']['netsnmphostinfo']['config'][0];

	if (!empty($nhisettings['syslocation'])) {
		$snmpd_config .= "sysLocation {$nhisettings['syslocation']}\n";
	}
	if (!empty($nhisettings['syscontact'])) {
		$snmpd_config .= "sysContact {$nhisettings['syscontact']}\n";
	}
	if (!empty($nhisettings['sysname'])) {
		$snmpd_config .= "sysName {$nhisettings['sysname']}\n";
	}
	if (!empty($nhisettings['sysdescr'])) {
		$snmpd_config .= "sysDescr {$nhisettings['sysdescr']}\n";
	}

	if (!empty($nhisettings['interface_fadeout'])) {
		$snmpd_config .= "interface_fadeout {$nhisettings['interface_fadeout']}\n";
	}
	if ($nhisettings['interface_replace_old'] == "yes") {
		$snmpd_config .= "interface_replace_old yes\n";
	} else {
		$snmpd_config .= "interface_replace_old no\n";
	}

	if (empty($nhisettings['disk_usage_percent'])) {
		$nhisettings['disk_usage_percent'] = "20";
	}
	/* Ignore /dev and its copies as they are not filesystems that need monitored */
	$snmpd_config .= "ignoreDisk /dev\n";
	$snmpd_config .= "ignoreDisk /var/dhcpd/dev\n";
	/* Monitor all disks that snmpd can find */
	$snmpd_config .= "includeAllDisks {$nhisettings['disk_usage_percent']}%\n";

	/* Load average settings each require the previous interval to be set,
	   otherwise the meaning is ambigious.
	   For example: load_1 [ load_5 [ load_15 ] ]
	 */
	if ($nhisettings['load_1']) {
		$snmpd_config .= "load {$nhisettings['load_1']}";
		if ($nhisettings['load_5']) {
			$snmpd_config .= " {$nhisettings['load_5']}";
			if ($nhisettings['load_15']) {
				$snmpd_config .= " {$nhisettings['load_15']}";
			}
		}
		$snmpd_config .= "\n";
	}

	/* Extended commands (formerly exec) and extendfix */
	/* TODO: Check if the parameters need quoting */
	if (is_array($nhisettings['row'])) {
		foreach ($nhisettings['row'] as $extend) {
			$snmpd_config .= "{$extend['ext_type']} " .
					 "{$extend['ext_miboid']} " .
					 "{$extend['ext_name']} " .
					 "{$extend['ext_prog']} " .
					 "{$extend['ext_args']}\n";
		}
	}

	/* SNMPv3 Users */
	$nusettings = &$config['installedpackages']['netsnmpusers']['config'];

	$snmpd_users_config = "";
	if (is_array($nusettings)) {
		foreach ($nusettings as $user) {
			/* To make it easier to define a user in one pass, the user settings have both user and cert settings */
			if (($user['snmpv3_type'] == "user") || ($user['snmpv3_type'] == "both")) {
				/* Create a user entry in the USM table. This only defines the user and its authentication method/transport */
				$createuser = "createUser \"{$user['username']}\" " .
						"{$user['authtype']} " .
						"\"{$user['password']}\"";
				/* Only add the privacy protocol if the user needs one */
				if ($user['privacyprotocol'] != "none") {
					if (empty($user['passphrase'])) {
						$user['passphrase'] = $user['password'];
					}
					$createuser .= " {$user['privacyprotocol']} " .
							"\"{$user['passphrase']}\"";
				}
				/* createUser directives go into a separate configuration file that gets changed by snmpd */
				$snmpd_users_config .= "{$createuser}\n";

				/* Each SNMPv3 user also needs an rouser or rwuser line to define its access */
				$snmpd_config .= "{$user['rorwuser']} " .
						 "-s {$user['secmodel']} " .
						 "\"{$user['username']}\"";
				if ($user['minseclev'] != "none") {
					$snmpd_config .= " {$user['minseclev']}";
					if (empty($user['baseoid'])) {
						$snmpd_config .= " {$user['baseoid']}";
					}
				}
				$snmpd_config .= "\n";
			}
			if (($user['snmpv3_type'] == "cert") || ($user['snmpv3_type'] == "both")) {
				/* Defines a mapping of a certificate parameter to an SNMPv3 username (defined previously) 
				   This requires the fingerprint of the certificate in order to identify it specifically,
				   and then the option defines which cert field to use, or a manual override to map to a
				   specific user directly.
				 */
				$snmpd_config .= "certSecName " .
						 "{$user['priority']} " .
						 "{$user['fingerprint']} " .
						 "--{$user['options']}";
				/* If SecName was chosen, define the username directly */
				if ($user['options'] == "sn") {
					$snmpd_config .= " {$user['secname']}";
				}
				$snmpd_config .= "\n";
			}
		}

		/* Don't bother to write the users config if there are no users */
		if (!empty($snmpd_users_config)) {
			file_put_contents($snmpd_users_file, $snmpd_users_config);
		}
	}

	/* SNMPv1 & SNMPv2c Communities */
	$ncsettings = &$config['installedpackages']['netsnmpcommunities']['config'];
	if (is_array($ncsettings)) {
		foreach ($ncsettings as $community) {
			/* Build the parameters first, add the type later as it could result in repetition. */
			$community_line = $community['community'];

			/* An OID restriction can only be specified if a source is also defined, use source "default" to set w/o network source */
			if (!empty($community['source'])) {
				/* TODO: Maybe some sanity checking to ensure that the source type matches the address family */
				$community_line .= " {$community['source']}";
				if (empty($community['baseoid'])) {
					$community_line .= " {$community['baseoid']}";
				}
			}

			/* Build the community type based on the address family, if both are needed, build both lines. */
			if (($community['commtype'] == "IPv4") || ($community['commtype'] == "both")) {
				$snmpd_config .= "{$community['rorwcommunity']} {$community_line}\n";
			}
			if (($community['commtype'] == "IPv6") || ($community['commtype'] == "both")) {
				$snmpd_config .= "{$community['rorwcommunity']}6 {$community_line}\n";
			}
		}
	}

	/* Trap Generation */
	$ntgsettings = &$config['installedpackages']['netsnmptrapgen']['config'][0];

	if (!empty($ntgsettings['trapcommunity'])) {
		$snmpd_config .= "trapcommunity {$ntgsettings['trapcommunity']}\n";
	}

	if (!empty($ntgsettings['authtrapenable'])) {
		$snmpd_config .= "authtrapenable {$ntgsettings['authtrapenable']}\n";
	}

	if (!empty($ntgsettings['linkupdownnotifications'])) {
		$snmpd_config .= "linkUpDownNotifications {$ntgsettings['linkupdownnotifications']}\n";
	}

	if (!empty($ntgsettings['defaultmonitors'])) {
		$snmpd_config .= "defaultMonitors {$ntgsettings['defaultmonitors']}\n";
	}

	if (!empty($ntgsettings['iquerysecname'])) {
		$snmpd_config .= "iquerySecName \"{$ntgsettings['iquerysecname']}\"\n";
		$snmpd_config .= "agentSecName \"{$ntgsettings['iquerysecname']}\"\n";
	}

	if (!empty($ntgsettings['v1trapaddress'])) {
		$snmpd_config .= "v1trapaddress {$ntgsettings['v1trapaddress']}\n";
	}

	if (!empty($ntgsettings['trapsink1_host'])) {
		$snmpd_config .= "trapsink {$ntgsettings['trapsink1_host']}";
		if (!empty($ntgsettings['trapsink1_community'])) {
			$snmpd_config .= " {$ntgsettings['trapsink1_community']}";
			if (!empty($ntgsettings['trapsink1_port'])) {
				$snmpd_config .= " {$ntgsettings['trapsink1_port']}";
			}
		}
		$snmpd_config .= "\n";
	}
	if (!empty($ntgsettings['trapsink3_host'])) {
		$snmpd_config .= "trapsink {$ntgsettings['trapsink3_host']}";
		if (!empty($ntgsettings['trapsink2_community'])) {
			$snmpd_config .= " {$ntgsettings['trapsink2_community']}";
			if (!empty($ntgsettings['trapsink2_port'])) {
				$snmpd_config .= " {$ntgsettings['trapsink2_port']}";
			}
		}
		$snmpd_config .= "\n";
	}
	if (!empty($ntgsettings['trapsink3_host'])) {
		$snmpd_config .= "trapsink {$ntgsettings['trapsink3_host']}";
		if (!empty($ntgsettings['trapsink3_community'])) {
			$snmpd_config .= " {$ntgsettings['trapsink3_community']}";
			if (!empty($ntgsettings['trapsink1_port'])) {
				$snmpd_config .= " {$ntgsettings['trapsink3_port']}";
			}
		}
		$snmpd_config .= "\n";
	}

	if (!empty($ntgsettings['trap2sink1_host'])) {
		$snmpd_config .= "trap2sink {$ntgsettings['trap2sink1_host']}";
		if (!empty($ntgsettings['trap2sink1_community'])) {
			$snmpd_config .= " {$ntgsettings['trap2sink1_community']}";
			if (!empty($ntgsettings['trap2sink1_port'])) {
				$snmpd_config .= " {$ntgsettings['trap2sink1_port']}";
			}
		}
		$snmpd_config .= "\n";
	}
	if (!empty($ntgsettings['trap2sink2_host'])) {
		$snmpd_config .= "trap2sink {$ntgsettings['trap2sink2_host']}";
		if (!empty($ntgsettings['trap2sink2_community'])) {
			$snmpd_config .= " {$ntgsettings['trap2sink2_community']}";
			if (!empty($ntgsettings['trap2sink2_port'])) {
				$snmpd_config .= " {$ntgsettings['trap2sink2_port']}";
			}
		}
		$snmpd_config .= "\n";
	}
	if (!empty($ntgsettings['trap2sink3_host'])) {
		$snmpd_config .= "trap2sink {$ntgsettings['trap2sink3_host']}";
		if (!empty($ntgsettings['trap2sink3_community'])) {
			$snmpd_config .= " {$ntgsettings['trap2sink3_community']}";
			if (!empty($ntgsettings['trap2sink3_port'])) {
				$snmpd_config .= " {$ntgsettings['trap2sink3_port']}";
			}
		}
		$snmpd_config .= "\n";
	}

	if (!empty($ntgsettings['informsink1_host'])) {
		$snmpd_config .= "informsink {$ntgsettings['informsink1_host']}";
		if (!empty($ntgsettings['informsink1_community'])) {
			$snmpd_config .= " {$ntgsettings['informsink1_community']}";
			if (!empty($ntgsettings['informsink1_port'])) {
				$snmpd_config .= " {$ntgsettings['informsink1_port']}";
			}
		}
		$snmpd_config .= "\n";
	}
	if (!empty($ntgsettings['informsink2_host'])) {
		$snmpd_config .= "informsink {$ntgsettings['informsink2_host']}";
		if (!empty($ntgsettings['informsink2_community'])) {
			$snmpd_config .= " {$ntgsettings['informsink2_community']}";
			if (!empty($ntgsettings['informsink2_port'])) {
				$snmpd_config .= " {$ntgsettings['informsink2_port']}";
			}
		}
		$snmpd_config .= "\n";
	}
	if (!empty($ntgsettings['informsink3_host'])) {
		$snmpd_config .= "informsink {$ntgsettings['informsink3_host']}";
		if (!empty($ntgsettings['informsink3_community'])) {
			$snmpd_config .= " {$ntgsettings['informsink3_community']}";
			if (!empty($ntgsettings['informsink3_port'])) {
				$snmpd_config .= " {$ntgsettings['informsink3_port']}";
			}
		}
		$snmpd_config .= "\n";
	}

	if (is_array($ntgsettings['row'])) {
		foreach ($ntgsettings['row'] as $monitor) {
			if (empty($monitor['monitor_name'])) {
				continue;
			}
			$snmpd_config .= "monitor {$monitor['monitor_options']} " .
					 "{$monitor['monitor_name']} " .
					 "{$monitor['monitor_expression']} " .
					 "{$monitor['monitor_notificationevent']} " .
					 "{$monitor['monitor_setevent']}\n";
		}
	}

	file_put_contents($snmpd_config_file, $snmpd_config);

	$rc_file_stop = <<<EOF
if [ -e /var/run/net_snmpd.pid ]; then
	/bin/kill -9 `/bin/cat /var/run/net_snmpd.pid`
	/bin/rm -f /var/run/net_snmpd.pid
fi
EOF;
	$rc_file_start = <<<EOF
# Ensure no other copies of the daemons are running or it breaks.
/usr/bin/killall -9 snmpd 2>/dev/null
sleep 1

/usr/local/sbin/snmpd -Ls d -V \
			-p /var/run/net_snmpd.pid \
			-M /usr/share/snmp/mibs/:/usr/local/share/snmp/mibs \
			-C \
			-c {$snmpd_config_file},{$snmpd_users_file}
EOF;
	write_rcfile(array(
			"file" => "net-snmpd.sh",
			"start" => $rc_file_start,
			"stop" =>  $rc_file_stop
		)
	);
	start_service('net-snmpd');
}

/* Write snmptrapd config file */
function netsnmp_resync_snmptrapd() {
	global $config, $snmptrapd_config_file;
	$nsettings = &$config['installedpackages']['netsnmptraplisten']['config'][0];

	if ($nsettings['enable_snmptrapd'] != "on") {
		/* stop service */
		return;
	}

	$snmptrapd_config = "";

	$agentaddresses = array();
	if (is_array($nsettings['row'])) {
		foreach ($nsettings['row'] as $agent) {
			$aa = "";
			if (!empty($agent['snmpport'])) {
				$aa = $agent['snmpport'];
			}
			if (!empty($agent['ipaddress'])) {
				$aa = "{$agent['ipaddress']}:{$aa}";
			}
			if (!empty($agent['transport'])) {
				$aa = "{$agent['transport']}:{$aa}";
			}
			if (!empty($aa)) {
				$agentaddresses[] = $aa;
			}
		}
	}
	if (!empty($agentaddresses)) {
		$snmptrapd_config .= "agentaddress " . implode(',', $agentaddresses) . "\n";
	}

/*
	<donotretainnotificationlogs>no</donotretainnotificationlogs>
	<donotlogtraps>no</donotlogtraps>
	<ignoreauthfailure>no</ignoreauthfailure>
	<logoption>-Ls d</logoption>
	<outputoption>-On</outputoption>
	<disableauthorization>no</disableauthorization>
	<authcommunity1>log pfsense</authcommunity1>
	<authcommunity2></authcommunity2>
	<authcommunity3></authcommunity3>
	<authuser1>log -s usm jimp</authuser1>
	<authuser2></authuser2>
	<authuser3></authuser3>
	<format1></format1>
	<format_custom1></format_custom1>
	<format_custom2></format_custom2>
	<format_custom3></format_custom3>
	<traphandle1></traphandle1>
	<traphandle2></traphandle2>
	<traphandle3></traphandle3>
	<custom_options></custom_options>
*/

	/* Dump custom options into the configuration as-is */
	if (!empty($nsettings['custom_options'])) {
		$snmptrapd_config .= "{$nsettings['custom_options']}\n";
	}

	file_put_contents($snmptrapd_config_file, $snmptrapd_config);
	// write_rcfile()
}
