# Entra ID Permission Management Tool

This tool helps administrators implement group-based RBAC (Role-Based Access Control) and PIM (Privileged Identity Management) for Entra ID by providing:

- A web UI built with [Flask](https://flask.palletsprojects.com/) and Bootstrap  
- Full Graph API integration via [`app.py`](app.py) and [`TokenManager`](app.py#L18)  
- Centralized credential handling with [`azure.identity.ClientSecretCredential`](app.py#L10)  
- Pagination, error handling, and minimum-scope token requests

  ![image](https://github.com/user-attachments/assets/4c690b00-c21a-420f-b38e-56838c356f91)


## Features

### Role Visibility  
- View all role definitions and assignments (users, groups, service principals)  
- Identify unused roles and removed (stale) identities  
- Track Active vs. Eligible (PIM) assignments  

### Group-Based Access Management  
- Create security groups per role/assignment type ([`/api/create-group/<role_id>`](app.py#L354))  
- Bulk transfer direct assignments to RBAC groups ([`/api/transfer-users/<role_id>/<assignment_type>`](app.py#L697))  
- Display group member lists via [`get_group_members`](app.py#L942)  

### Cleanup Tools  
- Detect and remove assignments for deleted principals ([`/cleanup-assignments/<role_id>`](app.py#L436))  
- “Clean Up All” removed identities from the UI  

## Requirements

- Python 3.8+  
- Microsoft Entra ID tenant & App Registration  
- [.env](.env) populated with `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`  
- See [requirements.txt](requirements.txt) for Python dependencies  

## Setup & Installation

```bash
git clone https://github.com/yourusername/EntraIdPermissionAutomation.git
cd EntraIdPermissionAutomation
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in your credentials
```

## Running the Application

```bash
python app.py
```

By default it listens on `http://0.0.0.0:5000/`. The single‐page UI is in [templates/index.html](templates/index.html).

## API Reference

- **GET** `/api/roles`  
  Returns all roles and enriched assignment data.  
- **GET** `/api/role/<role_id>`  
  Returns a single role’s data.  
- **POST** `/api/create-group/<role_id>`  
  Creates or returns an RBAC group.  
- **POST** `/api/transfer-users/<role_id>/<assignment_type>`  
  Moves direct assignments to a group.  
- **POST** `/cleanup-assignments/<role_id>`  
  Deletes stale role assignments.  
- **DELETE** `/api/remove-user/<role_id>/<assignment_type>/<user_id>`  
  Removes an individual user assignment.  
- **GET** `/health`  
  Health check endpoint.  

All request handling is in [`app.py`](app.py).

## Azure Best Practices

- Centralize credential management ([`get_credential`](app.py#L8))  
- Use Managed Identity in production instead of client secret  
- Request only minimum scopes (`"https://graph.microsoft.com/.default"`)  
- Implement token caching & refresh buffer (`TokenManager.get_token`)  
- Handle pagination via `@odata.nextLink` in [`make_graph_request`](app.py#L25)

> For more guidance, you can invoke the Azure best practices analyzer:  
> ```bash
> azure_development-get_best_practices --tool
> ```

## Contributing

1. Fork the repo  
2. Create a feature branch  
3. Submit a pull request  

Please follow the coding style in [`app.py`](app.py) and add tests where applicable.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
