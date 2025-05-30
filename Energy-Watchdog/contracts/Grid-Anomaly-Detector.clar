;; Smart Grid Anomaly Detection & Penalty System
;; An intelligent contract system that monitors electrical consumption patterns,
;; detects suspicious usage anomalies, and enforces automated penalty collection
;; for potential energy theft incidents across smart grid infrastructure.

;; CONSTANTS & CONFIGURATION

;; Contract Configuration
(define-constant contract-administrator tx-sender)

;; Error Code Definitions
(define-constant ERR-UNAUTHORIZED-ACCESS (err u100))
(define-constant ERR-RESOURCE-NOT-FOUND (err u101))
(define-constant ERR-DUPLICATE-ENTRY (err u102))
(define-constant ERR-INVALID-PARAMETERS (err u103))
(define-constant ERR-INSUFFICIENT-FUNDS (err u104))
(define-constant ERR-OPERATION-FORBIDDEN (err u105))
(define-constant ERR-METER-INACTIVE (err u106))
(define-constant ERR-INCIDENT-RESOLVED (err u107))
(define-constant ERR-INVALID-PRINCIPAL (err u108))
(define-constant ERR-METER-NOT-OWNED (err u109))

;; Anomaly Detection Thresholds (percentage values * 100 for integer precision)
(define-constant mild-anomaly-threshold u150)      ;; 50% consumption increase
(define-constant moderate-anomaly-threshold u200)  ;; 100% consumption increase
(define-constant severe-anomaly-threshold u300)    ;; 200% consumption increase

;; Penalty Structure (amounts in microSTX)
(define-constant mild-violation-penalty u1000000)     ;; 1 STX
(define-constant moderate-violation-penalty u5000000) ;; 5 STX
(define-constant severe-violation-penalty u10000000)  ;; 10 STX

;; System Limits
(define-constant maximum-location-length u100)
(define-constant minimum-consumption-value u1)
(define-constant maximum-meter-identifier u999999)
(define-constant maximum-incident-identifier u999999)

;; GLOBAL STATE VARIABLES

(define-data-var registered-meter-count uint u0)
(define-data-var accumulated-penalty-total uint u0)
(define-data-var system-treasury-balance uint u0)
(define-data-var next-available-meter-identifier uint u1)
(define-data-var next-available-incident-identifier uint u1)

;; DATA STRUCTURE DEFINITIONS

;; Smart Meter Registry
(define-map smart-meter-registry
  { meter-identifier: uint }
  {
    meter-owner-address: principal,
    installation-location: (string-ascii 100),
    historical-baseline-consumption: uint,
    latest-recorded-consumption: uint,
    last-update-block-height: uint,
    cumulative-reading-count: uint,
    operational-status: bool,
    anomaly-detection-count: uint
  }
)

;; Consumption Data Archive
(define-map consumption-data-archive
  { meter-identifier: uint, reading-sequence-number: uint }
  {
    recorded-consumption-value: uint,
    reading-timestamp: uint,
    blockchain-block-height: uint,
    calculated-anomaly-score: uint
  }
)

;; Security Incident Database
(define-map security-incident-database
  { incident-identifier: uint }
  {
    associated-meter-identifier: uint,
    detection-block-height: uint,
    violation-severity-level: (string-ascii 10),
    assessed-penalty-amount: uint,
    resolution-status: bool,
    resolution-block-height: (optional uint)
  }
)

;; Authorized Personnel Registry
(define-map authorized-personnel-registry
  { personnel-address: principal }
  { authorization-status: bool }
)

;; Property Owner Database
(define-map property-owner-database
  { owner-address: principal }
  { owned-meter-count: uint }
)

;; VALIDATION HELPER FUNCTIONS

;; Validate principal address (basic check for standard principal)
(define-private (validate-principal-address (address principal))
  (not (is-eq address 'SP000000000000000000002Q6VF78))
)

;; Validate meter identifier
(define-private (validate-meter-identifier (meter-id uint))
  (and 
    (> meter-id u0)
    (<= meter-id maximum-meter-identifier)
  )
)

;; Validate incident identifier
(define-private (validate-incident-identifier (incident-id uint))
  (and 
    (> incident-id u0)
    (<= incident-id maximum-incident-identifier)
  )
)

;; Validate consumption reading
(define-private (validate-consumption-reading (reading uint))
  (and 
    (>= reading minimum-consumption-value)
    (<= reading u999999999) ;; Reasonable upper limit
  )
)

;; Validate installation location
(define-private (validate-installation-location (location (string-ascii 100)))
  (and 
    (> (len location) u0)
    (<= (len location) maximum-location-length)
  )
)

;; UTILITY & HELPER FUNCTIONS

;; Administrative Access Verification
(define-private (verify-administrator-access)
  (is-eq tx-sender contract-administrator)
)

;; Personnel Authorization Verification
(define-private (verify-personnel-authorization (personnel-address principal))
  (default-to false 
    (get authorization-status 
      (map-get? authorized-personnel-registry { personnel-address: personnel-address })
    )
  )
)

;; Anomaly Score Calculation Engine
(define-private (compute-consumption-anomaly-score (baseline-consumption uint) (current-consumption uint))
  (if (is-eq baseline-consumption u0)
    u100 ;; Default neutral score when no baseline exists
    (/ (* current-consumption u100) baseline-consumption)
  )
)

;; Severity Classification System
(define-private (classify-violation-severity (anomaly-score uint))
  (if (>= anomaly-score severe-anomaly-threshold)
    "severe"
    (if (>= anomaly-score moderate-anomaly-threshold)
      "moderate"
      (if (>= anomaly-score mild-anomaly-threshold)
        "mild"
        "normal"
      )
    )
  )
)

;; Penalty Amount Calculator
(define-private (calculate-violation-penalty (severity-classification (string-ascii 10)))
  (if (is-eq severity-classification "severe")
    severe-violation-penalty
    (if (is-eq severity-classification "moderate")
      moderate-violation-penalty
      (if (is-eq severity-classification "mild")
        mild-violation-penalty
        u0
      )
    )
  )
)

;; Meter Ownership Verification
(define-private (verify-meter-ownership (meter-identifier uint) (claiming-owner principal))
  (match (map-get? smart-meter-registry { meter-identifier: meter-identifier })
    meter-record (is-eq (get meter-owner-address meter-record) claiming-owner)
    false
  )
)

;; Check if meter exists
(define-private (meter-exists (meter-identifier uint))
  (is-some (map-get? smart-meter-registry { meter-identifier: meter-identifier }))
)

;; Check if incident exists
(define-private (incident-exists (incident-identifier uint))
  (is-some (map-get? security-incident-database { incident-identifier: incident-identifier }))
)

;; SYSTEM INITIALIZATION & MANAGEMENT

;; Personnel Authorization Management
(define-public (grant-personnel-authorization (personnel-address principal))
  (begin
    (asserts! (verify-administrator-access) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (validate-principal-address personnel-address) ERR-INVALID-PRINCIPAL)
    (asserts! (not (is-eq personnel-address contract-administrator)) ERR-INVALID-PARAMETERS)
    
    (map-set authorized-personnel-registry 
      { personnel-address: personnel-address } 
      { authorization-status: true }
    )
    (ok true)
  )
)

(define-public (revoke-personnel-authorization (personnel-address principal))
  (begin
    (asserts! (verify-administrator-access) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (validate-principal-address personnel-address) ERR-INVALID-PRINCIPAL)
    
    (map-set authorized-personnel-registry 
      { personnel-address: personnel-address } 
      { authorization-status: false }
    )
    (ok true)
  )
)

;; Smart Meter Installation & Registration
(define-public (install-smart-meter (property-owner-address principal) (installation-location (string-ascii 100)))
  (let (
    (validated-owner property-owner-address)
    (validated-location installation-location)
    (new-meter-identifier (var-get next-available-meter-identifier))
    (current-owner-data (default-to { owned-meter-count: u0 } 
      (map-get? property-owner-database { owner-address: validated-owner })
    ))
  )
    (asserts! (verify-administrator-access) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (validate-principal-address validated-owner) ERR-INVALID-PRINCIPAL)
    (asserts! (validate-installation-location validated-location) ERR-INVALID-PARAMETERS)
    
    ;; Create new meter record
    (map-set smart-meter-registry
      { meter-identifier: new-meter-identifier }
      {
        meter-owner-address: validated-owner,
        installation-location: validated-location,
        historical-baseline-consumption: u0,
        latest-recorded-consumption: u0,
        last-update-block-height: block-height,
        cumulative-reading-count: u0,
        operational-status: true,
        anomaly-detection-count: u0
      }
    )
    
    ;; Update owner's meter inventory
    (map-set property-owner-database
      { owner-address: validated-owner }
      { owned-meter-count: (+ (get owned-meter-count current-owner-data) u1) }
    )
    
    ;; Update system counters
    (var-set next-available-meter-identifier (+ new-meter-identifier u1))
    (var-set registered-meter-count (+ (var-get registered-meter-count) u1))
    
    (ok new-meter-identifier)
  )
)

;; CONSUMPTION MONITORING & ANOMALY DETECTION

;; Consumption Data Recording & Analysis
(define-public (record-consumption-data (meter-identifier uint) (consumption-reading uint))
  (let (
    (validated-meter-id meter-identifier)
    (validated-consumption consumption-reading)
    (meter-record (unwrap! (map-get? smart-meter-registry { meter-identifier: validated-meter-id }) ERR-RESOURCE-NOT-FOUND))
    (baseline-consumption (get historical-baseline-consumption meter-record))
    (computed-anomaly-score (compute-consumption-anomaly-score baseline-consumption validated-consumption))
    (severity-classification (classify-violation-severity computed-anomaly-score))
    (new-reading-sequence (+ (get cumulative-reading-count meter-record) u1))
  )
    (asserts! (or (verify-administrator-access) (verify-personnel-authorization tx-sender)) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (validate-meter-identifier validated-meter-id) ERR-INVALID-PARAMETERS)
    (asserts! (validate-consumption-reading validated-consumption) ERR-INVALID-PARAMETERS)
    (asserts! (get operational-status meter-record) ERR-METER-INACTIVE)
    
    ;; Archive consumption data
    (map-set consumption-data-archive
      { meter-identifier: validated-meter-id, reading-sequence-number: new-reading-sequence }
      {
        recorded-consumption-value: validated-consumption,
        reading-timestamp: block-height,
        blockchain-block-height: block-height,
        calculated-anomaly-score: computed-anomaly-score
      }
    )
    
    ;; Update meter registry
    (map-set smart-meter-registry
      { meter-identifier: validated-meter-id }
      (merge meter-record {
        latest-recorded-consumption: validated-consumption,
        last-update-block-height: block-height,
        cumulative-reading-count: new-reading-sequence,
        historical-baseline-consumption: (if (is-eq baseline-consumption u0) validated-consumption baseline-consumption),
        anomaly-detection-count: (if (not (is-eq severity-classification "normal"))
                                    (+ (get anomaly-detection-count meter-record) u1)
                                    (get anomaly-detection-count meter-record))
      })
    )
    
    ;; Process potential security incident
    (if (not (is-eq severity-classification "normal"))
      (let (
        (incident-identifier (var-get next-available-incident-identifier))
        (penalty-amount (calculate-violation-penalty severity-classification))
      )
        (map-set security-incident-database
          { incident-identifier: incident-identifier }
          {
            associated-meter-identifier: validated-meter-id,
            detection-block-height: block-height,
            violation-severity-level: severity-classification,
            assessed-penalty-amount: penalty-amount,
            resolution-status: false,
            resolution-block-height: none
          }
        )
        (var-set next-available-incident-identifier (+ incident-identifier u1))
        (var-set accumulated-penalty-total (+ (var-get accumulated-penalty-total) penalty-amount))
        (ok { 
          data-recorded: true, 
          anomaly-detected: true, 
          incident-identifier: incident-identifier, 
          severity-level: severity-classification 
        })
      )
      (ok { 
        data-recorded: true, 
        anomaly-detected: false, 
        incident-identifier: u0, 
        severity-level: "normal" 
      })
    )
  )
)

;; INCIDENT RESOLUTION & PENALTY COLLECTION

;; Security Incident Resolution Processing
(define-public (resolve-security-incident (incident-identifier uint))
  (let (
    (validated-incident-id incident-identifier)
    (incident-record (unwrap! (map-get? security-incident-database { incident-identifier: validated-incident-id }) ERR-RESOURCE-NOT-FOUND))
    (penalty-amount (get assessed-penalty-amount incident-record))
  )
    (asserts! (validate-incident-identifier validated-incident-id) ERR-INVALID-PARAMETERS)
    (asserts! (not (get resolution-status incident-record)) ERR-INCIDENT-RESOLVED)
    
    ;; Process penalty payment
    (try! (stx-transfer? penalty-amount tx-sender (as-contract tx-sender)))
    
    ;; Update incident status
    (map-set security-incident-database
      { incident-identifier: validated-incident-id }
      (merge incident-record {
        resolution-status: true,
        resolution-block-height: (some block-height)
      })
    )
    
    ;; Update treasury balance
    (var-set system-treasury-balance (+ (var-get system-treasury-balance) penalty-amount))
    
    (ok true)
  )
)

;; Treasury Fund Management
(define-public (withdraw-treasury-funds (withdrawal-amount uint))
  (begin
    (asserts! (verify-administrator-access) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (> withdrawal-amount u0) ERR-INVALID-PARAMETERS)
    (asserts! (<= withdrawal-amount (var-get system-treasury-balance)) ERR-INSUFFICIENT-FUNDS)
    
    (try! (as-contract (stx-transfer? withdrawal-amount tx-sender contract-administrator)))
    (var-set system-treasury-balance (- (var-get system-treasury-balance) withdrawal-amount))
    
    (ok true)
  )
)

;; OPERATIONAL CONTROL FUNCTIONS

;; Meter Operational Status Management
(define-public (suspend-meter-operations (meter-identifier uint))
  (let (
    (validated-meter-id meter-identifier)
    (meter-record (unwrap! (map-get? smart-meter-registry { meter-identifier: validated-meter-id }) ERR-RESOURCE-NOT-FOUND))
  )
    (asserts! (validate-meter-identifier validated-meter-id) ERR-INVALID-PARAMETERS)
    (asserts! (or (verify-administrator-access) (verify-meter-ownership validated-meter-id tx-sender)) ERR-UNAUTHORIZED-ACCESS)
    
    (map-set smart-meter-registry
      { meter-identifier: validated-meter-id }
      (merge meter-record { operational-status: false })
    )
    
    (ok true)
  )
)

(define-public (resume-meter-operations (meter-identifier uint))
  (let (
    (validated-meter-id meter-identifier)
    (meter-record (unwrap! (map-get? smart-meter-registry { meter-identifier: validated-meter-id }) ERR-RESOURCE-NOT-FOUND))
  )
    (asserts! (verify-administrator-access) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (validate-meter-identifier validated-meter-id) ERR-INVALID-PARAMETERS)
    
    (map-set smart-meter-registry
      { meter-identifier: validated-meter-id }
      (merge meter-record { operational-status: true })
    )
    
    (ok true)
  )
)

;; QUERY & INFORMATION RETRIEVAL FUNCTIONS

;; Smart Meter Information Retrieval
(define-read-only (query-meter-information (meter-identifier uint))
  (if (validate-meter-identifier meter-identifier)
    (map-get? smart-meter-registry { meter-identifier: meter-identifier })
    none
  )
)

;; Consumption History Retrieval
(define-read-only (query-consumption-history (meter-identifier uint) (reading-sequence-number uint))
  (if (and (validate-meter-identifier meter-identifier) (> reading-sequence-number u0))
    (map-get? consumption-data-archive { meter-identifier: meter-identifier, reading-sequence-number: reading-sequence-number })
    none
  )
)

;; Security Incident Information
(define-read-only (query-incident-details (incident-identifier uint))
  (if (validate-incident-identifier incident-identifier)
    (map-get? security-incident-database { incident-identifier: incident-identifier })
    none
  )
)

;; System Statistics Overview
(define-read-only (query-system-statistics)
  {
    total-registered-meters: (var-get registered-meter-count),
    accumulated-penalties: (var-get accumulated-penalty-total),
    treasury-balance: (var-get system-treasury-balance),
    next-meter-id: (var-get next-available-meter-identifier),
    next-incident-id: (var-get next-available-incident-identifier)
  }
)

;; Personnel Authorization Status
(define-read-only (query-authorization-status (personnel-address principal))
  (if (validate-principal-address personnel-address)
    (verify-personnel-authorization personnel-address)
    false
  )
)

;; Property Owner Meter Count
(define-read-only (query-owner-meter-inventory (owner-address principal))
  (if (validate-principal-address owner-address)
    (default-to u0 (get owned-meter-count (map-get? property-owner-database { owner-address: owner-address })))
    u0
  )
)

;; Current Anomaly Score Calculation
(define-read-only (query-current-anomaly-score (meter-identifier uint))
  (if (validate-meter-identifier meter-identifier)
    (match (map-get? smart-meter-registry { meter-identifier: meter-identifier })
      meter-record (compute-consumption-anomaly-score 
                     (get historical-baseline-consumption meter-record) 
                     (get latest-recorded-consumption meter-record))
      u0
    )
    u0
  )
)

;; Meter Ownership Verification Query
(define-read-only (verify-meter-ownership-query (meter-identifier uint) (claiming-owner principal))
  (if (and (validate-meter-identifier meter-identifier) (validate-principal-address claiming-owner))
    (verify-meter-ownership meter-identifier claiming-owner)
    false
  )
)