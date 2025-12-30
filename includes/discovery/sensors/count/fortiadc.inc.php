<?php

/*
 * LibreNMS FortiADC count sensors
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

// Virtual Server metrics from FORTINET-FORTIADC-MIB::fadcVSTable
// Base OID: .1.3.6.1.4.1.12356.112.3.2
// Table columns:
// .2 = fadcVSName
// .5 = fadcVSNewConnections
// .6 = fadcVSConcurrent
// .7 = fadcVSThroughputKbps
// .9 = fadcVirtualServerWAF (optional)

try {
    // Fetch the whole virtual-server table grouped by index using MIB names
    $vs_table = snmpwalk_cache_multi_oid($device, 'fadcVSTable', [], 'FORTINET-FORTIADC-MIB');
    $vsNamesIdx = [];
    $newConnIdx = [];
    $concurrentIdx = [];
    $wafIdx = [];

    if (is_array($vs_table) && !empty($vs_table)) {
        foreach ($vs_table as $index => $row) {
            // Ensure values are strings/numeric, not arrays
            $name = isset($row['fadcVSName']) ? trim((string)$row['fadcVSName']) : '';
            if ($name === '') {
                continue;
            }

            $vsNamesIdx[$index] = $name;
            if (isset($row['fadcVSNewConnections'])) {
                $newConnIdx[$index] = (int)$row['fadcVSNewConnections'];
            }
            if (isset($row['fadcVSConcurrent'])) {
                $concurrentIdx[$index] = (int)$row['fadcVSConcurrent'];
            }
            if (isset($row['fadcVirtualServerWAF'])) {
                $wafIdx[$index] = (int)$row['fadcVirtualServerWAF'];
            }
        }
    }
} catch (\Exception $e) {
    // If SNMP fails, initialize empty arrays
    $vsNamesIdx = [];
    $newConnIdx = [];
    $concurrentIdx = [];
    $wafIdx = [];
}

// Discover sensors for each virtual server
if (! empty($vsNamesIdx) && is_array($vsNamesIdx)) {
    foreach ($vsNamesIdx as $index => $vsName) {
        $vsName = trim((string) $vsName);
        if ($vsName === '') {
            continue;
        }

        // New Connections per second
        if (isset($newConnIdx[$index])) {
            discover_sensor(
                null,
                'count',
                $device,
                '.1.3.6.1.4.1.12356.112.3.2.1.5.' . $index,
                'fadcVSNewConnections.' . $index,
                'fortiADC-vs',
                $vsName . ' - New Connections/sec',
                1,
                1,
                null,
                null,
                null,
                null,
                $newConnIdx[$index],
                'snmp',
                null,
                null,
                null,
                'Virtual Server Connections'
            );
        }

        // Concurrent connections
        if (isset($concurrentIdx[$index])) {
            discover_sensor(
                null,
                'count',
                $device,
                '.1.3.6.1.4.1.12356.112.3.2.1.6.' . $index,
                'fadcVSConcurrent.' . $index,
                'fortiADC-vs',
                $vsName . ' - Concurrent Connections',
                1,
                1,
                null,
                null,
                null,
                null,
                $concurrentIdx[$index],
                'snmp',
                null,
                null,
                null,
                'Virtual Server Connections'
            );
        }

        // WAF blocks (if available)
        if (isset($wafIdx[$index])) {
            discover_sensor(
                null,
                'count',
                $device,
                '.1.3.6.1.4.1.12356.112.3.2.1.9.' . $index,
                'fadcVirtualServerWAF.' . $index,
                'fortiADC-vs',
                $vsName . ' - WAF Blocks',
                1,
                1,
                null,
                null,
                null,
                null,
                $wafIdx[$index],
                'snmp',
                null,
                null,
                null,
                'Virtual Server Security'
            );
        }
    }
}

unset($vsNamesIdx, $newConnIdx, $concurrentIdx, $wafIdx, $index, $vsName);
