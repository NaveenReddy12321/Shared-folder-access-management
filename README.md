# Enterprise Shared Folder Access Management Tool

This project is a GUI-based PowerShell automation tool designed for enterprise environments to manage NTFS permissions on shared folders in a secure, auditable, and standardized manner.

The tool prioritizes Active Directory security groups over direct NTFS permissions, validates user identities, enforces administrative execution, and maintains a full audit trail of all actions performed.

---

## Problem Statement

In many enterprise environments, shared folder access is managed manually using File Explorer or ad-hoc scripts. This leads to several issues:

- Direct user-based NTFS permissions instead of security groups
- No audit trail of access changes
- Human errors while assigning or removing permissions
- Lack of standardization across teams
- Difficulty in compliance and security audits

This tool addresses these problems by providing a controlled, GUI-driven, and auditable access management solution.

---

## Key Features

- GUI-based execution using Windows Forms
- Administrative privilege enforcement
- Active Directory integration
- Preference for existing AD security groups over direct NTFS permissions
- Support for Read, Modify, and Full Control permissions
- Multiple user processing using semicolon-separated input
- AD user validation before permission changes
- Safe permission removal (only matching permissions are removed)
- Full CSV-based audit logging
- Session-level tracking using unique Session IDs
- Machine and executor identity tracking
- Robust input validation and error handling

---

## How It Works

1. The script validates administrative privileges and required dependencies.
2. The user provides:
   - Shared folder path
   - One or more AD users
   - Action (Add or Remove access)
   - Permission level
3. The tool inspects existing NTFS permissions on the folder.
4. If a matching AD security group is found:
   - Users are added to or removed from the group.
5. If no suitable group exists:
   - Permissions are applied directly to the user account.
6. All actions are logged to a central audit file.

---

## Audit Logging

All operations are logged in CSV format for easy review and compliance reporting.

### Log File Location
