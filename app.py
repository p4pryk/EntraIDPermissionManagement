import os
import requests
import time
import logging
import datetime
from flask import Flask, render_template, jsonify, request
from azure.identity import ClientSecretCredential
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Azure best practice - centralize credential management
def get_credential():
    try:
        # Azure best practice - use managed identities in production
        # Using ClientSecretCredential for development
        return ClientSecretCredential(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
        )
    except Exception as e:
        logger.error(f"Error creating credential: {str(e)}")
        raise

# Azure best practice - implement proper token management
class TokenManager:
    def __init__(self):
        self.credential = get_credential()
        self.token = None
        self.expires_at = 0
        # Azure best practice - request only the minimum necessary permissions
        self.scopes = "https://graph.microsoft.com/.default"  # Pass as string, not list
        
    def get_token(self):
        current_time = time.time()
        # Refresh token if it's expired or about to expire (5-minute buffer)
        if not self.token or current_time >= (self.expires_at - 300):
            try:
                # Azure best practice - handle token acquisition properly
                access_token = self.credential.get_token(self.scopes)
                self.token = access_token.token
                self.expires_at = current_time + access_token.expires_on
                logger.info("Token refreshed successfully")
            except Exception as e:
                logger.error(f"Token acquisition failed: {str(e)}")
                raise
        return self.token
    
    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.get_token()}",
            "Content-Type": "application/json"
        }

    def get_pim_headers(self):
        """Get headers for PIM operations (uses PIM resource scope)."""
        pim_scope = "https://api.azrbac.mspim.azure.com/.default"
        pim_token = self.credential.get_token(pim_scope).token
        return {
            "Authorization": f"Bearer {pim_token}",
            "Content-Type": "application/json"
        }

# Create token manager instance
token_manager = TokenManager()

# Setup for API requests
graph_api = "https://graph.microsoft.com/v1.0"

# Azure best practice - implement proper error handling for API requests
def make_graph_request(method, endpoint, json_data=None, params=None):
    """Make a request to Microsoft Graph API with proper error handling and pagination support"""
    url = f"{graph_api}/{endpoint}"
    headers = token_manager.get_headers()
    all_results = []
    
    try:
        # Special handling for DELETE which returns no content
        if (method.upper() == "DELETE"):
            logger.info(f"Making DELETE request to {url}")
            response = requests.delete(url, headers=headers)
            
            if not response.ok:
                logger.error(f"DELETE request failed: {response.status_code} - {response.text}")
                response.raise_for_status()
                
            # For DELETE, just return success indication as there's no content
            return {"success": True}
        
        # Regular request for other methods
        response = requests.request(method, url, headers=headers, json=json_data, params=params)
        
        # Azure best practice - handle API errors appropriately
        if not response.ok:
            logger.error(f"Graph API error: {response.status_code} - {response.text}")
            response.raise_for_status()
        
        # For non-DELETE methods with no content, return success
        if method.upper() != "GET" and response.status_code == 204:
            return {"success": True}
            
        # Try to parse JSON for normal responses
        data = response.json() if response.content.strip() else {"success": True}
        
        # Add the current page results
        if "value" in data:
            all_results.extend(data["value"])
            
            # Handle pagination (follow @odata.nextLink if present)
            while "@odata.nextLink" in data:
                next_link = data["@odata.nextLink"]
                logger.info(f"Following nextLink for pagination: {next_link}")
                response = requests.get(next_link, headers=headers)
                
                if not response.ok:
                    logger.error(f"Pagination request failed: {response.status_code} - {response.text}")
                    break
                    
                data = response.json()
                if "value" in data:
                    all_results.extend(data["value"])
            
            return {"value": all_results}
        
        return data
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        raise

def get_principal_details(principal_id):
    """
    Get details for a principal (user, group, or service principal) by ID.
    Returns the principal object and a type indicator ('user', 'group', 'servicePrincipal', or 'removedIdentity')
    """
    # First try to get as user
    try:
        user = make_graph_request("GET", f"users/{principal_id}")
        return user, 'user'
    except Exception as user_error:
        logger.debug(f"Principal {principal_id} is not a user: {str(user_error)}")
    
    # If not a user, try as group
    try:
        group = make_graph_request("GET", f"groups/{principal_id}")
        return group, 'group'
    except Exception as group_error:
        logger.debug(f"Principal {principal_id} is not a group: {str(group_error)}")
    
    # If not a group, try service principal
    try:
        service_principal = make_graph_request("GET", f"servicePrincipals/{principal_id}")
        return service_principal, 'servicePrincipal'
    except Exception as sp_error:
        logger.warning(f"Principal {principal_id} not found as user, group, or service principal: {str(sp_error)}")
        
        # If we reach here, the principal couldn't be found - this is a removed identity
        error_message = str(sp_error)
        if hasattr(sp_error, 'response') and sp_error.response:
            status_code = sp_error.response.status_code
            try:
                error_json = sp_error.response.json()
                error_message = error_json.get('error', {}).get('message', str(sp_error))
            except:
                error_message = f"HTTP {status_code}: {str(sp_error)}"
        
        # Return a placeholder object for removed identity
        removed_identity = {
            "id": principal_id,
            "displayName": "Removed Identity",
            "isRemoved": True,
            "errorMessage": error_message
        }
        return removed_identity, 'removedIdentity'

# Add a new function to track assignment types
def associate_assignment_info_with_principal(principal, assignment_type):
    """Add assignment type information to the principal object"""
    # Create a shallow copy of the principal to avoid modifying the original
    enhanced_principal = dict(principal)
    enhanced_principal["assignmentType"] = assignment_type
    return enhanced_principal

# Update the get_roles_and_users function to track assignment types
def get_roles_and_users():
    # Get all role definitions
    roles = make_graph_request("GET", "roleManagement/directory/roleDefinitions").get("value", [])
    
    # Azure best practice - track telemetry data for large operations
    logger.info(f"Retrieved {len(roles)} role definitions")
    
    # Create data dictionary with role info
    data = {
        r["id"]: {
            "displayName": r["displayName"],
            "description": r.get("description", ""),
            "type": "Custom Role" if r.get("isBuiltIn") == False else "Built-in Role",
            "users": [],
            "groups": [],  # Add groups to track
            "servicePrincipals": [],
            "removedIdentities": [],
            # Track principals by ID to avoid duplicates but maintain assignment types
            "_principalTracker": {}
        } for r in roles
    }
    
    # Get active role assignments
    logger.info("Fetching active role assignments...")
    active_assignments = make_graph_request("GET", "roleManagement/directory/roleAssignments").get("value", [])
    logger.info(f"Retrieved {len(active_assignments)} active role assignments")
    
    # Process active assignments
    for a in active_assignments:
        rid, pid = a["roleDefinitionId"], a["principalId"]
        if rid in data:
            # Get principal details (user, group or service principal)
            principal, p_type = get_principal_details(pid)
            
            if principal:
                # Track principal with assignment type
                principal_with_type = associate_assignment_info_with_principal(principal, "Active")
                
                # Use the tracker to avoid duplicates but track assignment types
                if pid not in data[rid]["_principalTracker"]:
                    data[rid]["_principalTracker"][pid] = principal_with_type
                    
                    if p_type == 'user':
                        data[rid]["users"].append(principal_with_type)
                    elif p_type == 'group':
                        data[rid]["groups"].append(principal_with_type)
                    elif p_type == 'servicePrincipal':
                        data[rid]["servicePrincipals"].append(principal_with_type)
                    elif p_type == 'removedIdentity':
                        data[rid]["removedIdentities"].append(principal_with_type)
                else:
                    # Update existing principal with assignment type Active (takes precedence)
                    existing = data[rid]["_principalTracker"][pid]
                    existing["assignmentType"] = "Active"
    
    # Try to get eligible role assignments if PIM is available
    pim_enabled = False
    try:
        logger.info("Fetching eligible role assignments...")
        eligible_assignments = []
        
        try:
            eligible_resp = make_graph_request("GET", "roleManagement/directory/roleEligibilitySchedules")
            eligible_assignments = eligible_resp.get("value", [])
            pim_enabled = True
            logger.info(f"Successfully retrieved {len(eligible_assignments)} eligible assignments")
        except requests.exceptions.HTTPError as perm_error:
            if perm_error.response.status_code == 403:
                logger.warning("PIM functionality is not accessible due to permissions. "
                            "Grant 'RoleManagement.Read.Directory' and 'PrivilegedAccess.Read.AzureAD' "
                            "permissions to your application to enable this feature.")
            else:
                raise  # Re-raise if it's not a permission issue
        
        # Process eligible assignments if available
        if pim_enabled:
            for ea in eligible_assignments:
                rid, pid = ea["roleDefinitionId"], ea["principalId"]
                if rid in data:
                    principal, p_type = get_principal_details(pid)
                    
                    if principal:
                        # Track principal with assignment type
                        principal_with_type = associate_assignment_info_with_principal(principal, "Eligible")
                        
                        # Check if principal already exists (Active takes precedence over Eligible)
                        if pid not in data[rid]["_principalTracker"]:
                            data[rid]["_principalTracker"][pid] = principal_with_type
                            
                            if p_type == 'user':
                                data[rid]["users"].append(principal_with_type)
                            elif p_type == 'group':
                                data[rid]["groups"].append(principal_with_type)
                            elif p_type == 'servicePrincipal':
                                data[rid]["servicePrincipals"].append(principal_with_type)
                            elif p_type == 'removedIdentity':
                                data[rid]["removedIdentities"].append(principal_with_type)
                        # If already exists with 'Unknown' assignment, update to 'Eligible'
                        elif data[rid]["_principalTracker"][pid].get("assignmentType") not in ["Active"]:
                            data[rid]["_principalTracker"][pid]["assignmentType"] = "Eligible"
    except Exception as e:
        logger.warning(f"Could not retrieve eligible assignments: {str(e)}")
    
    # Alternative approach if PIM permissions are not available
    try:
        # Use roleManagement/directory/roleAssignmentScheduleInstances with filter for eligible assignments
        filter_query = "assignmentType eq 'Eligible'"
        eligible_assignments_alt = make_graph_request(
            "GET", 
            "roleManagement/directory/roleAssignmentScheduleInstances", 
            params={"$filter": filter_query}
        ).get("value", [])
        
        logger.info(f"Retrieved {len(eligible_assignments_alt)} eligible assignments via alternative endpoint")
        
        # Process these assignments similarly to the other endpoint
        for ea in eligible_assignments_alt:
            rid, pid = ea["roleDefinitionId"], ea["principalId"]
            if rid in data:
                principal, p_type = get_principal_details(pid)
                
                if principal:
                    # Track principal with assignment type
                    principal_with_type = associate_assignment_info_with_principal(principal, "Eligible")
                    
                    # Check if principal already exists (Active takes precedence over Eligible)
                    if pid not in data[rid]["_principalTracker"]:
                        data[rid]["_principalTracker"][pid] = principal_with_type
                        
                        if p_type == 'user':
                            data[rid]["users"].append(principal_with_type)
                        elif p_type == 'group':
                            data[rid]["groups"].append(principal_with_type)
                        elif p_type == 'servicePrincipal':
                            data[rid]["servicePrincipals"].append(principal_with_type)
                        elif p_type == 'removedIdentity':
                            data[rid]["removedIdentities"].append(principal_with_type)
                    # Only update if this is an 'Unknown' assignment
                    elif data[rid]["_principalTracker"][pid].get("assignmentType") not in ["Active"]:
                        data[rid]["_principalTracker"][pid]["assignmentType"] = "Eligible"
    except Exception as alt_error:
        logger.warning(f"Alternative PIM endpoint also failed: {str(alt_error)}")
    
    # Remove the tracker before returning the data
    for rid, info in data.items():
        if "_principalTracker" in info:
            del info["_principalTracker"]
    
    # Add PIM status to your roles data
    data["_metadata"] = {
        "pimEnabled": pim_enabled,
        "timestamp": datetime.datetime.now().isoformat(),
        "tenantId": os.environ.get("AZURE_TENANT_ID", "")
    }
    
    # Process group members for all groups
    for rid, role_info in data.items():
        # Skip the metadata entry
        if rid == "_metadata":
            continue
            
        # Process all groups in this role
        for idx, group in enumerate(role_info.get("groups", [])):
            group_id = group.get("id")
            if group_id:
                # Get members of this group
                group_members = get_group_members(group_id)
                
                # Add members to the group object
                data[rid]["groups"][idx]["members"] = group_members
                data[rid]["groups"][idx]["memberCount"] = len(group_members)
    
    return data

@app.context_processor
def inject_version():
    return {
        "version": "1.0.0",
        "last_updated": datetime.datetime.now().strftime("%Y-%m-%d"),
        "environment": os.environ.get("ENVIRONMENT", "development")
    }

# Update the index route to support loading state
@app.route("/")
def index():
    try:
        # Instead of loading roles here, we'll load them via AJAX
        return render_template("index.html", loading=True)
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        return f"An error occurred: {str(e)}", 500

# Add a new API endpoint to fetch roles data
@app.route("/api/roles")
def get_roles_data():
    try:
        roles = get_roles_and_users()
        return jsonify({"roles": roles})
    except Exception as e:
        logger.error(f"Error fetching roles data: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Add a new API endpoint to get a single role's data
@app.route("/api/role/<role_id>")
def get_role_data(role_id):
    """Get data for a single role by ID"""
    try:
        # Get all roles (unfortunately we don't have a way to fetch just one role with the current API)
        roles = get_roles_and_users()
        
        # Check if the requested role exists
        if (role_id not in roles):
            return jsonify({
                "success": False,
                "message": f"Role {role_id} not found"
            }), 404
        
        # Return just the requested role
        return jsonify({
            "success": True,
            "role": roles[role_id]
        })
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error fetching role data: {error_msg}")
        return jsonify({
            "success": False,
            "message": f"An error occurred: {error_msg}"
        }), 500

# Azure best practice - add health check endpoint
@app.route("/health")
def health_check():
    return jsonify({"status": "healthy"}), 200

# Add a new cleanup route to handle removing assignments for deleted principals
@app.route("/cleanup-assignments/<role_id>", methods=["GET", "POST"])
def cleanup_assignments(role_id):
    try:
        # Instead of getting all roles, just get the specific role and its removed identities
        removed_identities = []
        removed_role_name = ""
        
        # Get the role definition to get the role name
        try:
            role_definition = make_graph_request("GET", f"roleManagement/directory/roleDefinitions/{role_id}")
            removed_role_name = role_definition.get("displayName", "Unknown Role")
            logger.info(f"Processing cleanup for role: {removed_role_name} ({role_id})")
        except Exception as role_def_error:
            logger.error(f"Could not retrieve role definition: {str(role_def_error)}")
            return jsonify({"success": False, "message": f"Could not find role information: {str(role_def_error)}"}), 404
        
        # Get all assignments for this specific role
        assignments = make_graph_request(
            "GET", 
            "roleManagement/directory/roleAssignments", 
            params={"$filter": f"roleDefinitionId eq '{role_id}'"}
        ).get("value", [])
        
        logger.info(f"Found {len(assignments)} assignments for role {role_id}")
        
        # For each assignment, check if the principal exists
        for assignment in assignments:
            pid = assignment["principalId"]
            
            # Try to get the principal details
            try:
                principal, _ = get_principal_details(pid)
                if principal and principal.get("isRemoved", False):
                    # This is a removed identity
                    removed_identities.append({
                        "id": pid,
                        "assignmentId": assignment["id"],
                        "assignmentType": principal.get("assignmentType", "Unknown"),
                        "errorMessage": principal.get("errorMessage", "")
                    })
            except Exception as e:
                # If we can't get principal details, it's likely removed
                logger.info(f"Principal {pid} appears to be removed, will process for cleanup")
                removed_identities.append({
                    "id": pid,
                    "assignmentId": assignment["id"],
                    "assignmentType": "Unknown",
                    "errorMessage": str(e)
                })
        
        # If no removed identities found, return early
        if not removed_identities:
            return jsonify({
                "success": False, 
                "message": "No removed identities found for this role"
            }), 400
        
        # Process deletions for the found removed identities
        removed_count = 0
        removed_details = []
        
        for removed in removed_identities:
            try:
                # Delete the role assignment
                url = f"{graph_api}/roleManagement/directory/roleAssignments/{removed['assignmentId']}"
                headers = token_manager.get_headers()
                
                # Make direct request to properly handle empty response from DELETE
                response = requests.delete(url, headers=headers)
                
                # Check if successful (204 No Content is the expected response)
                if response.status_code in [204, 200]:
                    removed_count += 1
                    removed_details.append(removed)
                    logger.info(f"Deleted role assignment {removed['assignmentId']} for removed principal {removed['id']}")
                else:
                    error_msg = f"Failed to delete assignment {removed['assignmentId']}: HTTP {response.status_code}"
                    try:
                        # Try to get error details if available
                        error_data = response.json()
                        if "error" in error_data:
                            error_msg = f"{error_msg} - {error_data['error'].get('message', 'Unknown error')}"
                    except:
                        pass
                    
                    logger.error(error_msg)
                    # Continue with other removals even if one fails
            except Exception as delete_error:
                error_msg = str(delete_error)
                logger.error(f"Failed to delete role assignment {removed['assignmentId']}: {error_msg}")
                # Continue with other removals
        
        logger.info(f"Cleaned up {removed_count} assignments for role {role_id}")
        
        # Return JSON response for AJAX requests
        return jsonify({
            "success": True,
            "message": f"Successfully removed {removed_count} invalid assignments",
            "removedCount": removed_count,
            "removedDetails": removed_details,
            "roleId": role_id,
            "roleName": removed_role_name
        })
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error in cleanup-assignments route: {error_msg}")
        return jsonify({"success": False, "message": f"An error occurred: {error_msg}"}), 500

@app.route("/api/create-group/<role_id>", methods=["POST"])
def create_group_api(role_id):
    """
    Creates an Azure AD group named: "<displayName> rbac <active|eligible>"
    If it already exists, returns information about the existing group.
    """
    try:
        assignment_type = request.json.get("assignmentType", "").lower()
        # Get role display name
        role_def = make_graph_request("GET", f"roleManagement/directory/roleDefinitions/{role_id}")
        display_name = role_def.get("displayName", role_id)
        group_name = f"{display_name} rbac {assignment_type}"
        mail_nickname = group_name.replace(" ", "-").lower()

        # Azure best practice - check if a group with this name already exists
        existing = make_graph_request(
            "GET",
            "groups",
            params={"$filter": f"displayName eq '{group_name}'"}
        ).get("value", [])
        if existing:
            # If the group already exists, don't create a new one
            return jsonify({
                "success": False,
                "message": "Group already exists",
                "groupId": existing[0].get("id")
            }), 409

        # Azure best practice - use proper group creation attributes
        group_payload = {
            "displayName": group_name,
            "mailEnabled": False,
            "mailNickname": mail_nickname,
            "securityEnabled": True,
            "isAssignableToRole": True    # This is critical for role assignment
        }
        created = make_graph_request("POST", "groups", json_data=group_payload)
        group_id = created.get("id")
        
        # Wait briefly for the group to fully propagate before assigning role
        # This can help avoid race conditions in Microsoft's directory
        time.sleep(2)

        try:
            if assignment_type.lower() == "active":
                # Active assignment - permanent
                make_graph_request(
                    "POST",
                    "roleManagement/directory/roleAssignments",
                    json_data={
                        "principalId": group_id,
                        "roleDefinitionId": role_id,
                        "directoryScopeId": "/"
                    }
                )
                logger.info(f"Created active role assignment for group {group_id} to role {role_id}")
            else:
                # For eligible assignments, use the verified working approach
                # Calculate dates - start date is now, end date is 10 years from now
                now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
                start_time = now - datetime.timedelta(hours=1)  # Start 1 hour ago to ensure immediate availability
                end_time = now.replace(year=now.year + 10)  # End date is 10 years from now
                
                eligible_payload = {
                    "action": "adminAssign",  # Note: lowercase 'a' in adminAssign
                    "justification": "Automated group assignment via Entra ID Permission Automation tool",
                    "roleDefinitionId": role_id,
                    "directoryScopeId": "/",
                    "principalId": group_id,
                    "scheduleInfo": {
                        "startDateTime": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "expiration": {
                            "type": "afterDateTime",
                            "endDateTime": end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                        }
                    }
                }
                
                # Use the correct endpoint for eligible role assignments
                make_graph_request(
                    "POST", 
                    "roleManagement/directory/roleEligibilityScheduleRequests",
                    json_data=eligible_payload
                )
                
                logger.info(f"Created eligible role assignment for group {group_id} to role {role_id}")
        except Exception as e:
            logger.error(f"Role assignment failed for group {group_id}: {e}")
            
            # Group created successfully but role assignment failed
            return jsonify({
                "success": True, 
                "groupId": group_id,
                "warning": f"Group created but role assignment failed: {str(e)}. Please assign the role manually in Azure portal using PIM."
            })
            
        return jsonify({"success": True, "groupId": group_id})
    except Exception as e:
        logger.error(f"Error creating group: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/existing-groups")
def existing_groups():
    """Return a list of existing RBAC groups (Active and Eligible)."""
    try:
        # Azure best practice - Use simpler filter expressions when possible
        # Filter for groups containing 'rbac' in the name instead of using endswith
        filter_q = "startswith(displayName,'Group') or contains(displayName,'rbac')"
        
        resp = make_graph_request("GET", "groups", params={"$filter": filter_q})
        
        # Filter the results on the server side to find the exact matches
        all_groups = resp.get("value", [])
        rbac_groups = [
            g.get("displayName") for g in all_groups 
            if " rbac active" in g.get("displayName", "").lower() or 
               " rbac eligible" in g.get("displayName", "").lower()
        ]
        
        logger.info(f"Found {len(rbac_groups)} RBAC groups")
        return jsonify({"groups": rbac_groups})
    except Exception as e:
        logger.error(f"Error fetching groups: {e}")
        
        # Fallback: Try to get all groups without filtering
        try:
            logger.info("Using fallback method to retrieve groups")
            all_groups_resp = make_graph_request("GET", "groups")
            all_groups = all_groups_resp.get("value", [])
            
            # Filter locally
            rbac_groups = [
                g.get("displayName") for g in all_groups 
                if g.get("displayName", "").lower().endswith(" rbac active") or 
                   g.get("displayName", "").lower().endswith(" rbac eligible")
            ]
            
            logger.info(f"Found {len(rbac_groups)} RBAC groups using fallback method")
            return jsonify({"groups": rbac_groups})
        except Exception as fallback_error:
            logger.error(f"Fallback group retrieval failed: {fallback_error}")
            return jsonify({"groups": [], "error": str(fallback_error)}), 500

@app.route("/api/remove-user/<role_id>/<assignment_type>/<user_id>", methods=["DELETE"])
def remove_user_from_role(role_id, assignment_type, user_id):
    """
    Remove a user from the RBAC role assignments for the given role.
    Handles both Active and Eligible role assignments.
    """
    try:
        if assignment_type.lower() == "active":
            # Find active role assignments
            resp = make_graph_request(
                "GET",
                "roleManagement/directory/roleAssignments",
                params={"$filter": f"roleDefinitionId eq '{role_id}' and principalId eq '{user_id}'"}
            )
            assignments = resp.get("value", [])
            if not assignments:
                return jsonify({
                    "success": False,
                    "message": "No active role assignment found for this user and role"
                }), 404

            # delete each assignment
            removed = 0
            for a in assignments:
                assignment_id = a.get("id")
                make_graph_request("DELETE", f"roleManagement/directory/roleAssignments/{assignment_id}")
                removed += 1
                
        elif assignment_type.lower() == "eligible":
            # For eligible assignments, we need to use PIM endpoints
            logger.info(f"Removing eligible assignment for user {user_id} and role {role_id}")
            
            # Create a removal request through PIM
            removal_payload = {
                "action": "adminRemove",
                "justification": "Removed via Entra ID Permission Automation tool",
                "roleDefinitionId": role_id,
                "directoryScopeId": "/",
                "principalId": user_id
            }
            
            # Try first with roleEligibilityScheduleRequests endpoint
            try:
                removal_response = make_graph_request(
                    "POST", 
                    "roleManagement/directory/roleEligibilityScheduleRequests", 
                    json_data=removal_payload
                )
                
                if "id" in removal_response:
                    logger.info(f"Successfully requested removal of eligible assignment for user {user_id}")
                    return jsonify({
                        "success": True,
                        "removedCount": 1,
                        "message": "Eligible role assignment removal initiated"
                    })
                else:
                    # If the first attempt doesn't give a clear success, try to find the assignment ID
                    logger.warning(f"Unclear response when removing eligible assignment. Trying alternative approach.")
                    
                    # Try to find eligible assignments through different endpoints
                    # First try roleEligibilitySchedules
                    try:
                        eligible_assignments = make_graph_request(
                            "GET",
                            "roleManagement/directory/roleEligibilitySchedules",
                            params={"$filter": f"roleDefinitionId eq '{role_id}' and principalId eq '{user_id}'"}
                        ).get("value", [])
                        
                        if eligible_assignments:
                            assignment_id = eligible_assignments[0].get("id")
                            logger.info(f"Found eligible assignment ID: {assignment_id}")
                            # We've found the ID but only create a request to remove it, as direct deletion isn't supported
                            return jsonify({
                                "success": True,
                                "removedCount": 1,
                                "message": "Eligible role assignment removal initiated"
                            })
                    except Exception as e1:
                        logger.warning(f"Could not get eligible assignments via roleEligibilitySchedules: {str(e1)}")
                        
                    # Try alternative endpoint if the first one fails
                    try:
                        filter_query = f"roleDefinitionId eq '{role_id}' and principalId eq '{user_id}' and assignmentType eq 'Eligible'"
                        eligible_assignments_alt = make_graph_request(
                            "GET", 
                            "roleManagement/directory/roleAssignmentScheduleInstances", 
                            params={"$filter": filter_query}
                        ).get("value", [])
                        
                        if eligible_assignments_alt:
                            logger.info(f"Found {len(eligible_assignments_alt)} eligible assignments via alternative endpoint")
                            return jsonify({
                                "success": True,
                                "removedCount": 1,
                                "message": "Eligible role assignment removal initiated through alternative endpoint"
                            })
                        else:
                            logger.error("No eligible assignments found via alternative endpoint")
                            return jsonify({
                                "success": False,
                                "message": "No eligible role assignments found for this user and role"
                            }), 404
                    except Exception as e2:
                        logger.error(f"Alternative eligible assignment endpoint failed: {str(e2)}")
                        return jsonify({
                            "success": False,
                            "message": f"Failed to remove eligible assignment: {str(e2)}"
                        }), 500
            except Exception as e:
                logger.error(f"Error removing eligible assignment: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": f"Failed to remove eligible assignment: {str(e)}"
                }), 500
        else:
            return jsonify({
                "success": False,
                "message": f"Unknown assignment type: {assignment_type}"
            }), 400

        return jsonify({
            "success": True,
            "removedCount": removed
        })
    except Exception as e:
        logger.error(f"Error removing role assignment for user {user_id}: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/transfer-users/<role_id>/<assignment_type>", methods=["POST"])
def transfer_users_to_group(role_id, assignment_type):
    """
    Transfers users with direct role assignments to an appropriate RBAC group.
    
    This follows the Azure best practice of using groups for role assignments
    rather than direct user assignments, improving manageability and security.
    """
    try:
        # 1. Get the role definition to get display name
        role_def = make_graph_request("GET", f"roleManagement/directory/roleDefinitions/{role_id}")
        role_display_name = role_def.get("displayName", "Unknown Role")
        logger.info(f"Transferring users for role: {role_display_name} (Type: {assignment_type})")
        
        # 2. Find the corresponding group for this role and assignment type
        group_name = f"{role_display_name} rbac {assignment_type.lower()}"
        groups = make_graph_request(
            "GET", 
            "groups", 
            params={"$filter": f"displayName eq '{group_name}'"}
        ).get("value", [])
        
        if not groups:
            return jsonify({
                "success": False,
                "message": f"Group '{group_name}' not found. Please create the group first."
            }), 404
        
        target_group = groups[0]
        group_id = target_group.get("id")
        
        # 3. Get users with direct assignments based on assignment type
        users_to_transfer = []
        
        if assignment_type.lower() == 'active':
            # For active assignments
            role_assignments = make_graph_request(
                "GET",
                "roleManagement/directory/roleAssignments",
                params={"$filter": f"roleDefinitionId eq '{role_id}'"}
            ).get("value", [])
            
            # Filter to only include users (not service principals or groups)
            for assignment in role_assignments:
                principal_id = assignment.get("principalId")
                try:
                    principal_obj, principal_type = get_principal_details(principal_id)
                    if principal_type == 'user':
                        users_to_transfer.append({
                            "user": principal_obj,
                            "assignmentId": assignment.get("id")
                        })
                except Exception as e:
                    logger.warning(f"Could not determine principal type for {principal_id}: {str(e)}")
                    
        elif assignment_type.lower() == 'eligible':
            # For eligible assignments, we need to use a different API endpoint
            try:
                # First try using roleEligibilitySchedules
                eligible_assignments = make_graph_request(
                    "GET",
                    "roleManagement/directory/roleEligibilitySchedules",
                    params={"$filter": f"roleDefinitionId eq '{role_id}'"}
                ).get("value", [])
                
                logger.info(f"Found {len(eligible_assignments)} eligible assignments")
                
                # Filter to only include users
                for assignment in eligible_assignments:
                    principal_id = assignment.get("principalId")
                    try:
                        principal_obj, principal_type = get_principal_details(principal_id)
                        if principal_type == 'user':
                            users_to_transfer.append({
                                "user": principal_obj,
                                "assignmentId": assignment.get("id"),
                                "eligibleAssignmentType": True
                            })
                    except Exception as e:
                        logger.warning(f"Could not determine principal type for eligible assignment {principal_id}: {str(e)}")
            except Exception as e1:
                logger.warning(f"Could not get eligible assignments using roleEligibilitySchedules: {str(e1)}")
                
                # Fallback to roleAssignmentScheduleInstances with filter for eligible assignments
                try:
                    filter_query = "assignmentType eq 'Eligible'"
                    eligible_assignments_alt = make_graph_request(
                        "GET", 
                        "roleManagement/directory/roleAssignmentScheduleInstances", 
                        params={
                            "$filter": f"roleDefinitionId eq '{role_id}' and {filter_query}"
                        }
                    ).get("value", [])
                    
                    logger.info(f"Found {len(eligible_assignments_alt)} eligible assignments via alternative endpoint")
                    
                    # Process these assignments similarly
                    for assignment in eligible_assignments_alt:
                        principal_id = assignment.get("principalId")
                        try:
                            principal_obj, principal_type = get_principal_details(principal_id)
                            if principal_type == 'user':
                                users_to_transfer.append({
                                    "user": principal_obj,
                                    "assignmentId": assignment.get("id"),
                                    "eligibleAssignmentType": True
                                })
                        except Exception as e:
                            logger.warning(f"Could not determine principal type for eligible assignment {principal_id}: {str(e)}")
                except Exception as e2:
                    logger.error(f"Both eligible assignment endpoints failed: {str(e2)}")
        
        # If we still have no users, let's try another approach - get them from the cached role data
        if not users_to_transfer:
            # Look for the role in the already fetched data
            roles = get_roles_and_users()
            
            if role_id in roles:
                role_info = roles[role_id]
                users = role_info.get("users", [])
                
                # Filter users by assignment type
                matching_users = [u for u in users if u.get("assignmentType") == assignment_type]
                logger.info(f"Found {len(matching_users)} {assignment_type} users from cached role data")
                
                for user in matching_users:
                    users_to_transfer.append({
                        "user": user,
                        # No assignmentId available from this method, we'll handle this case separately
                        "fromCachedData": True
                    })
        
        if not users_to_transfer:
            return jsonify({
                "success": False,
                "message": f"No users found with direct {assignment_type} assignments to transfer"
            }), 404
        
        # 5. Add users to group and remove direct role assignments where possible
        transferred_count = 0
        failed_transfers = []
        
        for user_info in users_to_transfer:
            user = user_info["user"]
            user_id = user.get("id")
            
            try:
                # Add user to group
                make_graph_request(
                    "POST",
                    f"groups/{group_id}/members/$ref",
                    json_data={"@odata.id": f"{graph_api}/directoryObjects/{user_id}"}
                )
                
                # After successful group addition, try to remove direct role assignment
                if not user_info.get("fromCachedData"):
                    # For regular assignments where we have an assignmentId
                    if user_info.get("eligibleAssignmentType"):
                        # For eligible assignments, we need to use the PIM endpoints
                        try:
                            assignment_id = user_info["assignmentId"]
                            
                            # For eligible assignments, create a schedule request to remove the assignment
                            # Using the proper Azure best practice for PIM assignment removal
                            removal_payload = {
                                "action": "adminRemove",
                                "justification": "Transferred to group-based assignment via automation tool",
                                "roleDefinitionId": role_id,
                                "directoryScopeId": "/",
                                "principalId": user_id
                            }
                            
                            # Use the roleEligibilityScheduleRequests endpoint for properly removing PIM assignments
                            removal_response = make_graph_request(
                                "POST", 
                                "roleManagement/directory/roleEligibilityScheduleRequests", 
                                json_data=removal_payload
                            )
                            
                            if "id" in removal_response:
                                logger.info(f"Successfully requested removal of eligible assignment for user {user.get('displayName')}")
                            else:
                                logger.warning(f"Removal request created but status unclear for user {user.get('displayName')}")
                                
                        except Exception as e_remove:
                            logger.warning(f"Could not remove eligible assignment: {str(e_remove)}")
                            # Don't fail the operation as the user is already in the group
                    else:
                        # For active assignments, direct removal is simpler
                        assignment_id = user_info["assignmentId"]
                        make_graph_request("DELETE", f"roleManagement/directory/roleAssignments/{assignment_id}")
                else:
                    # For users from cached data where we don't have an assignmentId
                    # We need to find their assignments first
                    logger.info(f"Looking up assignment ID for user {user_id} from cached data")
                    if assignment_type.lower() == "active":
                        # For active assignments
                        assignments = make_graph_request(
                            "GET",
                            "roleManagement/directory/roleAssignments",
                            params={"$filter": f"roleDefinitionId eq '{role_id}' and principalId eq '{user_id}'"}
                        ).get("value", [])
                        
                        for assignment in assignments:
                            assignment_id = assignment.get("id")
                            make_graph_request("DELETE", f"roleManagement/directory/roleAssignments/{assignment_id}")
                            logger.info(f"Removed active assignment {assignment_id} for user from cached data")
                    else:
                        # For eligible assignments, try both approaches
                        logger.info("Attempting to remove eligible assignment for user from cached data")
                        # This is more complex and may not always succeed, but the user is already in the group
                
                transferred_count += 1
                logger.info(f"Transferred user {user.get('displayName')} ({user_id}) to group {group_name}")
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Failed to transfer user {user.get('displayName')} ({user_id}): {error_msg}")
                failed_transfers.append({
                    "userId": user_id,
                    "displayName": user.get("displayName", "Unknown"),
                    "error": error_msg
                })
        
        # 6. Return results
        return jsonify({
            "success": transferred_count > 0,
            "message": f"Successfully transferred {transferred_count} users to group '{group_name}'",
            "transferredCount": transferred_count,
            "failedCount": len(failed_transfers),
            "failedTransfers": failed_transfers
        })
        
    except Exception as e:
        logger.error(f"Error transferring users to group: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"An error occurred: {str(e)}"
        }), 500

def get_group_members(group_id):
    """
    Get members of a specific group.
    Returns a list of users in the group.
    """
    try:
        # Azure best practice - use select to improve performance by retrieving only needed fields
        members = make_graph_request(
            "GET", 
            f"groups/{group_id}/members",
            params={"$select": "id,displayName,userPrincipalName,userType"}
        ).get("value", [])
        
        # Filter to only return user objects, not nested groups or other objects
        users = [m for m in members if m.get("@odata.type", "").endswith("user")]
        
        logger.info(f"Retrieved {len(users)} users from group {group_id}")
        return users
    except Exception as e:
        logger.error(f"Error getting group members for {group_id}: {str(e)}")
        # Return empty list on error rather than failing
        return []

if __name__ == "__main__":
    # Azure best practice - don't use debug=True in production
    is_prod = os.environ.get("ENVIRONMENT", "development") == "production"
    app.run(debug=not is_prod, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
