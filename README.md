# Entra ID Permission Management Tool

This tool helps administrators implement security best practices for Entra ID permissions by providing:

- Group-based RBAC (Role-Based Access Control) implementation  
- PIM (Privileged Identity Management) adoption tracking and facilitation  
- Identification and cleanup of stale identity permissions  
- User-friendly web interface for role management operations  
![image](https://github.com/user-attachments/assets/3373defe-e30b-4cbc-b95f-4fa16c5a5b8d)


## Key Features

### Role Assignment Visibility

- View all directory role definitions with filtering options  
- Track Active vs. Eligible (PIM) assignments at a glance  
- Identify unused roles and stale identities  
- See detailed breakdown of all role assignment types (users, groups, service principals)  

### Group-Based Access Management

- Create role-specific security groups with appropriate naming convention  
- Transfer individual user permissions to centrally managed groups  
- Analyze group membership with detailed member lists  
- Implement both Active and Eligible (PIM) group assignments  

### Security Cleanup Tools

- Detect and remove assignments for deleted principals  
- Bulk clean-up of all stale identity assignments  
- Individual user permission removal from within the interface  
- Detailed error handling and status reporting  

## Requirements

- Python 3.8+  
- Microsoft Entra ID tenant with Global Admin or Privileged Role Admin access  
- App Registration with appropriate Microsoft Graph API permissions:  
  - `RoleManagement.Read.Directory`  
  - `RoleManagement.ReadWrite.Directory`  
  - `Directory.Read.All`  
  - `PrivilegedAccess.Read.AzureAD` (for PIM functionality)  
- Environment variables in `.env` file:
  - `AZURE_TENANT_ID`  
  - `AZURE_CLIENT_ID`  
  - `AZURE_CLIENT_SECRET`  

## Setup & Installation

```bash
git clone https://github.com/yourusername/EntraIdPermissionAutomation.git
cd EntraIdPermissionAutomation
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env  # Then edit with your credentials
````

## Running the Application

The application will be available at [http://localhost:5000/](http://localhost:5000/).
The single-page UI in `index.html` provides an intuitive management interface.

## API Reference

| Endpoint                                                 | Method | Description                                     |
| -------------------------------------------------------- | ------ | ----------------------------------------------- |
| `/api/roles`                                             | GET    | Returns all roles with enriched assignment data |
| `/api/role/<role_id>`                                    | GET    | Returns data for a single role                  |
| `/api/create-group/<role_id>`                            | POST   | Creates an RBAC group for a role                |
| `/api/transfer-users/<role_id>/<assignment_type>`        | POST   | Transfers direct assignments to a group         |
| `/api/remove-user/<role_id>/<assignment_type>/<user_id>` | DELETE | Removes an individual assignment                |
| `/cleanup-assignments/<role_id>`                         | POST   | Removes stale assignments                       |
| `/api/existing-groups`                                   | GET    | Returns RBAC groups in the directory            |
| `/health`                                                | GET    | Health check endpoint                           |

