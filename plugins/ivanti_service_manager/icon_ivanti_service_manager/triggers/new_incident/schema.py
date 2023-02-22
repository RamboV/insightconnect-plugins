# GENERATED BY KOMAND SDK - DO NOT EDIT
import insightconnect_plugin_runtime
import json


class Component:
    DESCRIPTION = "Check for new incident"


class Input:
    
    FREQUENCY = "frequency"
    

class Output:
    
    INCIDENT = "incident"
    

class NewIncidentInput(insightconnect_plugin_runtime.Input):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "frequency": {
      "type": "integer",
      "title": "Frequency",
      "description": "How often the trigger should check for new detections in seconds",
      "default": 10,
      "order": 1
    }
  },
  "required": [
    "frequency"
  ]
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)


class NewIncidentOutput(insightconnect_plugin_runtime.Output):
    schema = json.loads("""
   {
  "type": "object",
  "title": "Variables",
  "properties": {
    "incident": {
      "$ref": "#/definitions/incident",
      "title": "Incident",
      "description": "New Incident",
      "order": 1
    }
  },
  "required": [
    "incident"
  ],
  "definitions": {
    "incident": {
      "type": "object",
      "title": "incident",
      "properties": {
        "ActualCategory": {
          "type": "string",
          "title": "Actual Category",
          "description": "Actual category",
          "order": 2
        },
        "ActualCategory_Valid": {
          "type": "string",
          "title": "Actual Category Valid",
          "description": "Actual category valid",
          "order": 1
        },
        "ActualService": {
          "type": "string",
          "title": "Actual Service",
          "description": "Actual service",
          "order": 73
        },
        "ActualService_Valid": {
          "type": "string",
          "title": "Actual Service Valid",
          "description": "Actual service valid",
          "order": 72
        },
        "AlternateContactLink": {
          "type": "string",
          "title": "Alternate Contact Link",
          "description": "Alternate contact link",
          "order": 54
        },
        "AlternateContactLink_Category": {
          "type": "string",
          "title": "Alternate Contact Link Category",
          "description": "Alternate contact link category",
          "order": 52
        },
        "AlternateContactLink_RecID": {
          "type": "string",
          "title": "Alternate Contact Link Rec ID",
          "description": "Alternate contact link rec ID",
          "order": 53
        },
        "AlternateContactPhone": {
          "type": "string",
          "title": "Alternate Contact Phone",
          "description": "Altername contact phone number",
          "order": 69
        },
        "Approver": {
          "type": "string",
          "title": "Approver",
          "description": "Approver",
          "order": 95
        },
        "Approver_Valid": {
          "type": "string",
          "title": "Approver Valid",
          "description": "Approver valid",
          "order": 94
        },
        "Category": {
          "type": "string",
          "title": "Category",
          "description": "Category",
          "order": 4
        },
        "Category_Valid": {
          "type": "string",
          "title": "Category Valid",
          "description": "Category valid",
          "order": 3
        },
        "CauseCode": {
          "type": "string",
          "title": "Cause Code",
          "description": "Cause code",
          "order": 6
        },
        "CauseCode_Valid": {
          "type": "string",
          "title": "Cause Code Valid",
          "description": "Cause code valid",
          "order": 5
        },
        "ClosedBy": {
          "type": "string",
          "title": "Closed By",
          "description": "Closed by",
          "order": 7
        },
        "ClosedDateTime": {
          "type": "string",
          "title": "Closed Date Time",
          "description": "Closed date and time",
          "order": 8
        },
        "ClosedDuration": {
          "type": "integer",
          "title": "Closed Duration",
          "description": "Closed duration",
          "order": 9
        },
        "Cost": {
          "type": "string",
          "title": "Cost",
          "description": "Cost",
          "order": 92
        },
        "CostPerMinute": {
          "type": "string",
          "title": "Cost Per Minute",
          "description": "Cost per minute",
          "order": 76
        },
        "CostPerMinute_Currency": {
          "type": "string",
          "title": "Cost Per Minute Currency",
          "description": "Cost per minute currency",
          "order": 74
        },
        "CostPerMinute_CurrencyValid": {
          "type": "string",
          "title": "Cost Per Minute Currency Valid",
          "description": "Cost per minute currency valid",
          "order": 75
        },
        "Cost_Currency": {
          "type": "string",
          "title": "Cost Currency",
          "description": "Cost currency",
          "order": 90
        },
        "Cost_CurrencyValid": {
          "type": "string",
          "title": "Cost Currency Valid",
          "description": "Cost currency valid",
          "order": 91
        },
        "CreatedBy": {
          "type": "string",
          "title": "Created By",
          "description": "Created by",
          "order": 10
        },
        "CreatedByType": {
          "type": "string",
          "title": "Created By Type",
          "description": "Created by type",
          "order": 88
        },
        "CreatedDateTime": {
          "type": "string",
          "title": "Created Date Time",
          "description": "Created date and time",
          "order": 11
        },
        "CustomerDepartment": {
          "type": "string",
          "title": "Customer Department",
          "description": "Customer department",
          "order": 71
        },
        "CustomerLocation": {
          "type": "string",
          "title": "Customer Location",
          "description": "Customer location",
          "order": 63
        },
        "CustomerLocation_Valid": {
          "type": "string",
          "title": "Customer Location Valid",
          "description": "Customer location valid",
          "order": 62
        },
        "Email": {
          "type": "string",
          "title": "Email",
          "description": "Email",
          "order": 12
        },
        "EntityLink": {
          "type": "string",
          "title": "Entity Link",
          "description": "Entity link",
          "order": 104
        },
        "EntityLink_Category": {
          "type": "string",
          "title": "Entity Link Category",
          "description": "Entity link category",
          "order": 102
        },
        "EntityLink_RecID": {
          "type": "string",
          "title": "Entity Link Rec ID",
          "description": "Entity link rec ID",
          "order": 103
        },
        "FirstCallResolution": {
          "type": "boolean",
          "title": "First Call Resolution",
          "description": "First call resolution",
          "order": 13
        },
        "HoursOfOperation": {
          "type": "string",
          "title": "Hours Of Operation",
          "description": "Created by",
          "order": 58
        },
        "HoursOfOperation_Valid": {
          "type": "string",
          "title": "Hours Of Operation Valid",
          "description": "Hours of operation valid",
          "order": 57
        },
        "Impact": {
          "type": "string",
          "title": "Impact",
          "description": "Impact",
          "order": 15
        },
        "Impact_Valid": {
          "type": "string",
          "title": "Impact Valid",
          "description": "Impact valid",
          "order": 14
        },
        "IncidentNetworkUserName": {
          "type": "string",
          "title": "Incident Network User Name",
          "description": "Incident network user name",
          "order": 100
        },
        "IncidentNumber": {
          "type": "integer",
          "title": "IncidentNumber",
          "description": "Incident number",
          "order": 16
        },
        "IsApprovalNeeded": {
          "type": "boolean",
          "title": "Is Approval Needed",
          "description": "Is approval needed",
          "order": 93
        },
        "IsDSMTaskExisted": {
          "type": "boolean",
          "title": "Is DSM Task Existed By",
          "description": "Is DSM task existed",
          "order": 96
        },
        "IsInFinalState": {
          "type": "boolean",
          "title": "Is In Final State",
          "description": "Is the incident in its final state",
          "order": 77
        },
        "IsMasterIncident": {
          "type": "boolean",
          "title": "Is Master Incident",
          "description": "Is master incidint",
          "order": 105
        },
        "IsNewRecord": {
          "type": "boolean",
          "title": "Is New Record",
          "description": "Is new record",
          "order": 51
        },
        "IsNotification": {
          "type": "boolean",
          "title": "Is Notification",
          "description": "Is notification",
          "order": 17
        },
        "IsReclassifiedForResolution": {
          "type": "boolean",
          "title": "Is Reclassified For Resolution",
          "description": "Is reclassified for resolution",
          "order": 78
        },
        "IsRelatedIncidentResolutionUpdate": {
          "type": "boolean",
          "title": "Is Related Incident Resolution Update",
          "description": "Is related incident resolution update",
          "order": 109
        },
        "IsRelatedIncidentUpdate": {
          "type": "boolean",
          "title": "Is Related Incident Update",
          "description": "Is related incident update",
          "order": 108
        },
        "IsReportedByAlternateContact": {
          "type": "boolean",
          "title": "Is Reported By Alternate Contact",
          "description": "Is reported by alternate contact",
          "order": 64
        },
        "IsResolvedByMaster": {
          "type": "boolean",
          "title": "Is Resolved By Master",
          "description": "Is resolved by master",
          "order": 106
        },
        "IsUnRead": {
          "type": "boolean",
          "title": "Is Unread",
          "description": "Is unread",
          "order": 110
        },
        "IsVIP": {
          "type": "boolean",
          "title": "Is VIP",
          "description": "Is the ticket raised by VIP",
          "order": 18
        },
        "IsWorkAround": {
          "type": "boolean",
          "title": "Is Work Around",
          "description": "Is there a workaround available",
          "order": 19
        },
        "KnowledgeLink": {
          "type": "string",
          "title": "Knowledge Link",
          "description": "Knowledge link",
          "order": 81
        },
        "KnowledgeLink_Category": {
          "type": "string",
          "title": "Knowledge Link Category",
          "description": "Knowledge Link category",
          "order": 79
        },
        "KnowledgeLink_RecID": {
          "type": "string",
          "title": "Knowledge Link Rec ID",
          "description": "Knowledge link rec ID",
          "order": 80
        },
        "LastModBy": {
          "type": "string",
          "title": "Last Modified By",
          "description": "Last modified by",
          "order": 20
        },
        "LastModDateTime": {
          "type": "string",
          "title": "Last Modified Date Time",
          "description": "Last modified date and time",
          "order": 21
        },
        "LoginId": {
          "type": "string",
          "title": "Login ID",
          "description": "Login ID",
          "order": 45
        },
        "OrgUnitLink": {
          "type": "string",
          "title": "Org Unit Link",
          "description": "Organization unit link",
          "order": 84
        },
        "OrgUnitLink_Category": {
          "type": "string",
          "title": "Org Unit Link Category",
          "description": "Organization unit link category",
          "order": 82
        },
        "OrgUnitLink_RecID": {
          "type": "string",
          "title": "Org Unit Link Rec ID",
          "description": "Organization unit link rec ID",
          "order": 83
        },
        "OrganizationUnitID": {
          "type": "string",
          "title": "Organization Unit ID",
          "description": "Organization unit ID",
          "order": 65
        },
        "Owner": {
          "type": "string",
          "title": "Owner",
          "description": "Owner",
          "order": 47
        },
        "OwnerEmail": {
          "type": "string",
          "title": "Owner Email",
          "description": "Owner email",
          "order": 59
        },
        "OwnerTeam": {
          "type": "string",
          "title": "Owner Team",
          "description": "Owner team",
          "order": 49
        },
        "OwnerTeamEmail": {
          "type": "string",
          "title": "Owner Team Email",
          "description": "Owner team email",
          "order": 60
        },
        "OwnerTeam_Valid": {
          "type": "string",
          "title": "Owner Team Valid",
          "description": "Owner team valid",
          "order": 48
        },
        "OwnerType": {
          "type": "string",
          "title": "Owner Type",
          "description": "Owner type",
          "order": 50
        },
        "Owner_Valid": {
          "type": "string",
          "title": "Owner Valid",
          "description": "Owner valid",
          "order": 46
        },
        "OwnershipAssignmentEmail": {
          "type": "string",
          "title": "Ownership Assignment Email",
          "description": "Ownership assignment email",
          "order": 61
        },
        "OwningOrgUnitId": {
          "type": "string",
          "title": "Owning Org Unit ID",
          "description": "Owning org unit ID",
          "order": 86
        },
        "OwningOrgUnitId Valid": {
          "type": "string",
          "title": "Owning Org Unit ID Valid",
          "description": "Owning org unit ID valid",
          "order": 85
        },
        "Phone": {
          "type": "string",
          "title": "Phone",
          "description": "Phone",
          "order": 22
        },
        "Priority": {
          "type": "string",
          "title": "Priority",
          "description": "Priority",
          "order": 24
        },
        "Priority_Valid": {
          "type": "string",
          "title": "Priority Valid By",
          "description": "Priority valid by",
          "order": 23
        },
        "ProfileFullName": {
          "type": "string",
          "title": "Profile Full Name",
          "description": "Full name of who raised the incident",
          "order": 25
        },
        "ProfileLink": {
          "type": "string",
          "title": "Profile Link",
          "description": "Profile link",
          "order": 28
        },
        "ProfileLink_Category": {
          "type": "string",
          "title": "Profile Link Category",
          "description": "Profile link category",
          "order": 26
        },
        "ProfileLink_RecID": {
          "type": "string",
          "title": "Profile Link Rec ID",
          "description": "Profile link Rec ID",
          "order": 27
        },
        "Progress Bar Position": {
          "type": "string",
          "title": "Progress Bar Position",
          "description": "Progress bar position",
          "order": 87
        },
        "RecId": {
          "type": "string",
          "title": "Rec ID",
          "description": "Rec ID",
          "order": 29
        },
        "ReportingOrgUnitID": {
          "type": "string",
          "title": "Reporting Org Unit ID",
          "description": "Reporting organization unit ID",
          "order": 67
        },
        "ReportingOrgUnitID_Valid": {
          "type": "string",
          "title": "Reporting Org Unit ID Valid",
          "description": "Reporting organization unit ID valid",
          "order": 66
        },
        "Resolution": {
          "type": "string",
          "title": "Resolution",
          "description": "Resolution",
          "order": 30
        },
        "ResolvedBy": {
          "type": "string",
          "title": "Resolved By",
          "description": "Resolved by",
          "order": 56
        },
        "ResolvedDateTime": {
          "type": "string",
          "title": "Resolved Date Time",
          "description": "Resolved date and time",
          "order": 55
        },
        "SLA": {
          "type": "string",
          "title": "SLA",
          "description": "SLA",
          "order": 33
        },
        "SLADisplayText": {
          "type": "string",
          "title": "SLA Display Text",
          "description": "SLA display text",
          "order": 89
        },
        "SLALink": {
          "type": "string",
          "title": "SLA Link",
          "description": "SLA link",
          "order": 36
        },
        "SLALink_Category": {
          "type": "string",
          "title": "SLA Link Category",
          "description": "SLA link Category",
          "order": 34
        },
        "SLALink_RecID": {
          "type": "string",
          "title": "SLA Link Rec ID",
          "description": "SLA link rec ID",
          "order": 35
        },
        "SendSurveyNotification": {
          "type": "boolean",
          "title": "Send Survey Notification",
          "description": "Send survey notification",
          "order": 101
        },
        "Service": {
          "type": "string",
          "title": "Service",
          "description": "Service",
          "order": 32
        },
        "ServiceOwnerEmail": {
          "type": "string",
          "title": "Service Owner Email",
          "description": "Service owner email",
          "order": 107
        },
        "Service_Valid": {
          "type": "string",
          "title": "Service Valid",
          "description": "Service valid",
          "order": 31
        },
        "SocialTextHeader": {
          "type": "string",
          "title": "Social Text Header",
          "description": "Social text header",
          "order": 97
        },
        "Source": {
          "type": "string",
          "title": "Source",
          "description": "Source",
          "order": 38
        },
        "Source_Valid": {
          "type": "string",
          "title": "Source Valid",
          "description": "Source valid",
          "order": 37
        },
        "Status": {
          "type": "string",
          "title": "Status",
          "description": "Created by",
          "order": 40
        },
        "Status_Valid": {
          "type": "string",
          "title": "Status Valid",
          "description": "Status valid",
          "order": 39
        },
        "Subject": {
          "type": "string",
          "title": "Subject",
          "description": "Incident subject",
          "order": 41
        },
        "Symptom": {
          "type": "string",
          "title": "Symptom",
          "description": "Symptoms of the indident",
          "order": 42
        },
        "TeamManagerEmail": {
          "type": "string",
          "title": "Team Manager Email",
          "description": "Team manager email",
          "order": 70
        },
        "TypeOfIncident": {
          "type": "string",
          "title": "Type Of Incident",
          "description": "Type of incident",
          "order": 68
        },
        "Urgency": {
          "type": "string",
          "title": "Urgency",
          "description": "Urgency",
          "order": 44
        },
        "Urgency_Valid": {
          "type": "string",
          "title": "Urgency Valid",
          "description": "Urgency valid",
          "order": 43
        },
        "helpdesk_Priority": {
          "type": "string",
          "title": "Helpdesk Priority",
          "description": "Helpdesk priority",
          "order": 99
        },
        "helpdesk_Priority_Valid": {
          "type": "string",
          "title": "Helpdesk Priority Valid",
          "description": "Helpdesk priority valid",
          "order": 98
        }
      }
    }
  }
}
    """)

    def __init__(self):
        super(self.__class__, self).__init__(self.schema)
