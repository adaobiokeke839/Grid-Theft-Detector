# Smart Grid Anomaly Detection & Penalty System

An intelligent Stacks blockchain smart contract that monitors electrical consumption patterns, detects suspicious usage anomalies, and enforces automated penalty collection for potential energy theft incidents across smart grid infrastructure.

## Overview

This smart contract provides a comprehensive solution for utilities and energy companies to:
- Register and manage smart meters across their grid
- Monitor consumption patterns and detect anomalies
- Automatically classify violations by severity
- Enforce penalty collection through blockchain transactions
- Maintain transparent records of all incidents and resolutions

## Features

### Smart Meter Management
- Register new smart meters with location and owner information
- Track consumption baselines and historical data
- Suspend/resume meter operations
- Verify meter ownership

### Anomaly Detection
- Real-time consumption monitoring
- Automatic anomaly score calculation
- Three-tier severity classification (mild, moderate, severe)
- Configurable detection thresholds

### Automated Penalty System
- Severity-based penalty calculation
- Automatic incident creation for violations
- STX-based penalty collection
- Treasury fund management

### 👥 Access Control
- Administrator-only system management
- Authorized personnel for data recording
- Owner-specific meter operations

## Contract Constants

### Anomaly Detection Thresholds
- **Mild Anomaly**: 150% (50% increase over baseline)
- **Moderate Anomaly**: 200% (100% increase over baseline)  
- **Severe Anomaly**: 300% (200% increase over baseline)

### Penalty Structure
- **Mild Violation**: 1 STX
- **Moderate Violation**: 5 STX
- **Severe Violation**: 10 STX

### System Limits
- Maximum location length: 100 characters
- Maximum meter ID: 999,999
- Maximum incident ID: 999,999

## Core Functions

### Administrative Functions

#### `grant-personnel-authorization(personnel-address)`
Grants authorization to personnel for recording consumption data.
- **Access**: Administrator only
- **Parameters**: `personnel-address` (principal)
- **Returns**: `(ok true)` on success

#### `revoke-personnel-authorization(personnel-address)`
Revokes personnel authorization.
- **Access**: Administrator only
- **Parameters**: `personnel-address` (principal)
- **Returns**: `(ok true)` on success

#### `install-smart-meter(property-owner-address, installation-location)`
Registers a new smart meter in the system.
- **Access**: Administrator only
- **Parameters**: 
  - `property-owner-address` (principal)
  - `installation-location` (string-ascii 100)
- **Returns**: `(ok meter-identifier)` on success

### Operational Functions

#### `record-consumption-data(meter-identifier, consumption-reading)`
Records consumption data and performs anomaly detection.
- **Access**: Administrator or authorized personnel
- **Parameters**:
  - `meter-identifier` (uint)
  - `consumption-reading` (uint)
- **Returns**: Object with recording status and anomaly information

#### `resolve-security-incident(incident-identifier)`
Resolves a security incident by collecting the penalty.
- **Access**: Any user (must pay penalty)
- **Parameters**: `incident-identifier` (uint)
- **Returns**: `(ok true)` on successful resolution

#### `suspend-meter-operations(meter-identifier)`
Suspends meter operations.
- **Access**: Administrator or meter owner
- **Parameters**: `meter-identifier` (uint)
- **Returns**: `(ok true)` on success

#### `resume-meter-operations(meter-identifier)`
Resumes suspended meter operations.
- **Access**: Administrator only
- **Parameters**: `meter-identifier` (uint)
- **Returns**: `(ok true)` on success

### Treasury Management

#### `withdraw-treasury-funds(withdrawal-amount)`
Withdraws funds from the system treasury.
- **Access**: Administrator only
- **Parameters**: `withdrawal-amount` (uint, in microSTX)
- **Returns**: `(ok true)` on success

### Query Functions

#### `query-meter-information(meter-identifier)`
Retrieves complete meter information.
- **Parameters**: `meter-identifier` (uint)
- **Returns**: Meter record or `none`

#### `query-consumption-history(meter-identifier, reading-sequence-number)`
Retrieves historical consumption data.
- **Parameters**: 
  - `meter-identifier` (uint)
  - `reading-sequence-number` (uint)
- **Returns**: Consumption record or `none`

#### `query-incident-details(incident-identifier)`
Retrieves security incident information.
- **Parameters**: `incident-identifier` (uint)
- **Returns**: Incident record or `none`

#### `query-system-statistics()`
Returns overall system statistics.
- **Returns**: Object with system metrics

#### `query-authorization-status(personnel-address)`
Checks personnel authorization status.
- **Parameters**: `personnel-address` (principal)
- **Returns**: `true` if authorized, `false` otherwise

#### `query-owner-meter-inventory(owner-address)`
Returns the number of meters owned by an address.
- **Parameters**: `owner-address` (principal)
- **Returns**: Number of owned meters (uint)

#### `query-current-anomaly-score(meter-identifier)`
Calculates current anomaly score for a meter.
- **Parameters**: `meter-identifier` (uint)
- **Returns**: Anomaly score (uint)

#### `verify-meter-ownership-query(meter-identifier, claiming-owner)`
Verifies meter ownership.
- **Parameters**:
  - `meter-identifier` (uint)
  - `claiming-owner` (principal)
- **Returns**: `true` if owner is verified, `false` otherwise

## Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 100 | ERR-UNAUTHORIZED-ACCESS | Insufficient permissions |
| 101 | ERR-RESOURCE-NOT-FOUND | Requested resource doesn't exist |
| 102 | ERR-DUPLICATE-ENTRY | Entry already exists |
| 103 | ERR-INVALID-PARAMETERS | Invalid input parameters |
| 104 | ERR-INSUFFICIENT-FUNDS | Insufficient funds for operation |
| 105 | ERR-OPERATION-FORBIDDEN | Operation not allowed |
| 106 | ERR-METER-INACTIVE | Meter is not operational |
| 107 | ERR-INCIDENT-RESOLVED | Incident already resolved |
| 108 | ERR-INVALID-PRINCIPAL | Invalid principal address |
| 109 | ERR-METER-NOT-OWNED | Meter not owned by sender |

## Data Structures

### Smart Meter Registry
Stores comprehensive meter information including:
- Owner address and installation location
- Consumption baselines and latest readings
- Operational status and anomaly counts

### Consumption Data Archive
Historical consumption records with:
- Consumption values and timestamps
- Block heights and anomaly scores

### Security Incident Database
Violation records containing:
- Associated meter and detection details
- Severity levels and penalty amounts
- Resolution status and timestamps

## Usage Examples

### 1. Installing a Smart Meter
```clarity
(contract-call? .smart-grid-contract install-smart-meter 
  'SP1234...OWNER 
  "123 Main Street, Apt 4B")
```

### 2. Recording Consumption Data
```clarity
(contract-call? .smart-grid-contract record-consumption-data 
  u1 ;; meter-identifier
  u150) ;; consumption-reading
```

### 3. Resolving an Incident
```clarity
(contract-call? .smart-grid-contract resolve-security-incident 
  u1) ;; incident-identifier
```

### 4. Querying Meter Information
```clarity
(contract-call? .smart-grid-contract query-meter-information u1)
```

## Security Considerations

- **Access Control**: Multiple permission levels ensure proper authorization
- **Input Validation**: All inputs are validated before processing
- **State Consistency**: Atomic operations maintain data integrity
- **Principal Verification**: Address validation prevents invalid operations

## Deployment Requirements

- Stacks blockchain testnet/mainnet
- STX tokens for contract deployment and penalty payments
- Administrator account for initial setup

## Integration

This contract can be integrated with:
- IoT smart meter devices
- Utility management systems
- Energy monitoring dashboards
- Automated billing systems