# ADSecurityScanner

A comprehensive Active Directory security scanner built with Tauri (Rust backend) and React (frontend), featuring deep AD integration for enterprise security auditing and operations.

## Features

### 🛡️ Core Capabilities
- **Incident Management**: Create, track, and resolve security incidents with priority levels
- **Active Directory Integration**: Seamlessly connect to AD for user management operations
- **User Account Management**: Search and disable user accounts during incident response
- **Real-time Dashboard**: Monitor incidents, system health, and response metrics
- **Audit Logging**: All actions are logged for compliance and forensics

### 🔐 Security Features
- Secure LDAP/AD communication
- Role-based access control ready
- Encrypted credential handling
- Comprehensive audit trail
- Incident response workflow automation

### 💻 Technical Stack
- **Backend**: Rust with Tauri 2.0
- **Frontend**: React 19 + Next.js 15
- **AD Integration**: LDAP3 protocol library
- **UI**: Tailwind CSS with dark theme optimized for SOC environments

## Installation

### Prerequisites
- Rust 1.70+ (install from https://rustup.rs/)
- Node.js 18+ and npm
- Active Directory server access (for AD features)

### Setup

1. **Clone and Install Dependencies**
\`\`\`bash
npm install
\`\`\`

2. **Development Mode**
\`\`\`bash
npm run tauri:dev
\`\`\`

3. **Build for Production**
\`\`\`bash
npm run tauri:build
\`\`\`

The built application will be in `src-tauri/target/release/`.

## Configuration

### Active Directory Connection
Navigate to the **AD Connection** tab and provide:
- **LDAP Server**: Your AD server address (e.g., `ldap.company.com:389`)
- **Username**: Service account DN or UPN
- **Password**: Service account password
- **Base DN**: Search base (e.g., `DC=company,DC=com`)

### Security Recommendations
1. Use a dedicated service account with minimal required permissions
2. Implement LDAPS (port 636) for encrypted connections in production
3. Enable audit logging on your AD server
4. Regularly review disabled user accounts
5. Implement MFA for platform access

## Usage

### Incident Response Workflow

1. **Create Incident**: Document security events with priority and affected systems
2. **Search Users**: Quickly find compromised or suspicious user accounts
3. **Disable Accounts**: Immediately disable accounts during active incidents
4. **Track Progress**: Update incident status through investigation lifecycle
5. **Document Actions**: Add response actions for audit and review

### User Management

- Search by name, username, or email
- View user details including groups and status
- Disable accounts with documented reasons
- View account status in real-time

## Architecture

\`\`\`
adsecurityscanner/
├── src-tauri/              # Rust backend
│   ├── src/
│   │   ├── main.rs         # Tauri commands and app state
│   │   ├── ad_client.rs    # Active Directory integration
│   │   └── incident.rs     # Incident data structures
│   └── Cargo.toml
├── app/                    # Next.js frontend
│   ├── page.tsx            # Main application shell
│   └── globals.css         # Theme and styling
├── components/             # React components
│   ├── dashboard-view.tsx
│   ├── incident-manager.tsx
│   ├── user-management.tsx
│   └── ad-connection.tsx
└── lib/
    └── tauri-api.ts        # TypeScript API bindings
\`\`\`

## Development

### Adding New Commands

1. Define the Rust command in `src-tauri/src/main.rs`
2. Add TypeScript bindings in `src/lib/tauri-api.ts`
3. Use in React components

### Customization

- **Theme**: Modify `app/globals.css` design tokens
- **AD Operations**: Extend `src-tauri/src/ad_client.rs`
- **Incident Fields**: Update `src-tauri/src/incident.rs`

## Important Notes

⚠️ **Active Directory Operations**: The current implementation includes a simulated disable operation. For production use, you must implement the actual LDAP modify operation to set the `userAccountControl` attribute.

⚠️ **Security**: This platform handles sensitive security operations. Always:
- Use encrypted connections (LDAPS)
- Implement proper authentication and authorization
- Enable comprehensive audit logging
- Follow your organization's security policies
- Test thoroughly in a non-production environment first

## License

MIT License - See LICENSE file for details

## Support

For issues and questions:
- Review the documentation
- Check Active Directory connectivity
- Verify service account permissions
- Review application logs

---

Built for enterprise security teams to respond faster and more effectively to security incidents.
