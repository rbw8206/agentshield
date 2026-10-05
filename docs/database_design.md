# AgentShield - Database Design

## 1. Users

- user_id
- name
- email
- role
- password_hash

## 2. Agents

- agent_id
- name
- type
- status
- risk_level

## 3. Roles

- role_id
- name
- description

## 4. Permissions

- permission_id
- action
- resource
- description

## 5. Agent Permissions

- agent_id
- permission_id

## 6. Resources

- resource_id
- name
- type
- sensitivity_level

## 7. Policies

- policy_id
- name
- description
- condition
- action
- priority
- enabled

## 8. Action Requests

- request_id
- agent_id
- action
- resource_id
- timestamp
- status

## 9. Risk Events

- risk_id
- request_id
- risk_score
- risk_level
- factors

## 10. Approvals

- approval_id
- request_id
- admin_id
- decision
- timestamp
- reason

## 11. Audit Logs

- log_id
- request_id
- agent_id
- action
- resource_id
- risk_score
- decision
- reason
- timestamp

## 12. Security Incidents

- incident_id
- request_id
- agent_id
- threat_type
- severity
- description
- status
- timestamp