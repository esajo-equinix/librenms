<?php

/*
 * LibreNMS FortiADC state sensors
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.  Please see LICENSE.txt at the top level of
 * the source code distribution for details.
 *
 * @package    LibreNMS
 * @link       https://www.librenms.org
 *
 * @copyright  2025 LibreNMS Contributors
 */

// Define state indexes for Virtual Server Status and Health
$statusStates = [
    ['value' => 0, 'generic' => 0, 'graph' => 1, 'descr' => 'Enable'],
    ['value' => 1, 'generic' => 2, 'graph' => 0, 'descr' => 'Disable'],
];
create_state_index('fadcVSStatus', $statusStates);

$healthStates = [
    ['value' => 0, 'generic' => 0, 'graph' => 1, 'descr' => 'HEALTHY'],
    ['value' => 1, 'generic' => 2, 'graph' => 0, 'descr' => 'DEAD'],
];
create_state_index('fadcVSHealth', $healthStates);

// Virtual Server state metrics from FORTINET-FORTIADC-MIB::fadcVSTable
// Base OID: .1.3.6.1.4.1.12356.112.3.2
// .2 = fadcVSName
// .3 = fadcVSStatus (Enable/Disable)
// .4 = fadcVSHealth (HEALTHY/DEAD)

try {
    // Use grouped table to ensure textual values for names/status/health
    $vs_table = snmpwalk_cache_multi_oid($device, 'fadcVSTable', [], 'FORTINET-FORTIADC-MIB');
    $vsNames = [];
    $vsStatus = [];
    $vsHealth = [];

    if (is_array($vs_table) && !empty($vs_table)) {
        foreach ($vs_table as $index => $row) {
            $name = isset($row['fadcVSName']) ? trim((string)$row['fadcVSName']) : '';
            if ($name === '') {
                continue;
            }
            $vsNames[$index] = $name;
            if (isset($row['fadcVSStatus'])) {
                $vsStatus[$index] = $row['fadcVSStatus'];
            }
            if (isset($row['fadcVSHealth'])) {
                $vsHealth[$index] = $row['fadcVSHealth'];
            }
        }
    }
} catch (\Exception $e) {
    $vsNames = [];
    $vsStatus = [];
    $vsHealth = [];
}

// Discover state sensors for each virtual server
if (! empty($vsNames) && is_array($vsNames)) {
    foreach ($vsNames as $index => $vsName) {
        $vsName = trim((string) $vsName);
        if ($vsName === '') {
            continue;
        }

        // Virtual Server Status (string, e.g. "Enable" or "Disable")
        if (isset($vsStatus[$index])) {
            $statusStr = strtoupper(trim((string) $vsStatus[$index]));
            $statusValue = 0; // default to Enable/OK
            if ($statusStr === 'DISABLE') {
                $statusValue = 1;
            }

            discover_sensor(
                null,
                'state',
                $device,
                '.1.3.6.1.4.1.12356.112.3.2.1.3.' . $index,
                'fadcVSStatus.' . $index,
                'fadcVSStatus',
                $vsName . ' - Status',
                1,
                1,
                null,
                null,
                null,
                null,
                $statusValue,
                'snmp',
                null,
                null,
                null,
                'Virtual Server Status'
            );
        }

        // Virtual Server Health (string, e.g. "HEALTHY" or "DEAD")
        if (isset($vsHealth[$index])) {
            $healthStr = strtoupper(trim((string) $vsHealth[$index]));
            $healthValue = 0; // default to HEALTHY/OK
            if ($healthStr === 'DEAD') {
                $healthValue = 1;
            }

            discover_sensor(
                null,
                'state',
                $device,
                '.1.3.6.1.4.1.12356.112.3.2.1.4.' . $index,
                'fadcVSHealth.' . $index,
                'fadcVSHealth',
                $vsName . ' - Health',
                1,
                1,
                null,
                null,
                null,
                null,
                $healthValue,
                'snmp',
                null,
                null,
                null,
                'Virtual Server Health'
            );
        }
    }
}

unset($vsNames, $vsStatus, $vsHealth, $index, $vsName, $statusStr, $statusValue, $healthStr, $healthValue, $statusStates, $healthStates);
