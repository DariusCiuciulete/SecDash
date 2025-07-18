# SecDash Frontend - Security Dashboard

A modern, React-based web interface for SecDash that provides a comprehensive security scanning and vulnerability management platform.

## 🚀 Features

### 📊 **Dashboard Overview**
- Real-time scan monitoring with progress tracking
- Statistics cards showing security metrics
- Interactive charts for scan status and tool usage
- Recent activity feed with severity indicators

### 🏠 **Home/Workspaces**
- Central hub for security operations
- Quick action buttons for common tasks
- Active scans overview with live progress
- Activity timeline with severity color coding

### 🎯 **Assets & Targets Management**
- Add and manage scan targets (hosts, networks, web apps)
- Support for multiple asset types:
  - Individual hosts (IP addresses)
  - Network ranges (CIDR notation)
  - Web applications (URLs)
  - Domain names
- Asset tagging and categorization
- Status tracking and last scan information

### 🔧 **Scan Launcher**
- Intuitive interface for configuring scans
- Support for multiple security tools:
  - **Nmap**: Network discovery and port scanning
  - **ZAP**: Web application security testing
  - **Metasploit**: Penetration testing framework
  - **tshark**: Network traffic analysis
- Predefined scan profiles for each tool
- Custom target input or asset selection
- Advanced options for power users

### 📈 **Dashboard & Results**
- Comprehensive scan results visualization
- Interactive tables with sortable columns
- Progress tracking for active scans
- Detailed findings breakdown
- Export capabilities for reporting

### 🐛 **Vulnerability Management**
- Centralized vulnerability tracking
- Severity-based filtering and sorting
- Status management (Open, Acknowledged, Fixed, False Positive)
- Detailed vulnerability information including:
  - CVE references
  - Impact assessment
  - Remediation recommendations
  - Custom notes and annotations
- CVSS scoring and risk assessment

### ⚙️ **Settings & Integrations**
- **SIEM Integration**: 
  - Splunk HEC (HTTP Event Collector)
  - Elasticsearch with API key authentication
- **Notification System**:
  - Email alerts for critical findings
  - SMTP configuration
- **API Management**:
  - Generate and manage API keys
  - Access control and audit logging
- **Security Settings**:
  - Session management
  - Authentication requirements
  - Audit logging

## 🎨 Design & UX

### Dark Security Theme
- Professional dark theme optimized for security professionals
- High contrast design for long working sessions
- Terminal-inspired color scheme with green accents
- Responsive design for desktop and mobile

### Modern Material-UI Components
- Clean, professional interface
- Consistent iconography and spacing
- Accessible design patterns
- Smooth animations and transitions

### Security-Focused Features
- Color-coded severity indicators
- Status badges for quick identification
- Progress bars for real-time feedback
- Monospace fonts for technical data

## 🏗️ Technical Architecture

### Frontend Stack
- **React 19.1.0**: Modern React with hooks and context
- **Material-UI v5**: Component library with dark theme
- **React Router v6**: Client-side routing
- **Recharts**: Data visualization and charts
- **Custom Hooks**: Reusable API and state management

### Project Structure
```
frontend/src/
├── components/          # Reusable UI components
│   └── Layout.js       # Main navigation and layout
├── pages/              # Main application pages
│   ├── Home.js         # Dashboard overview
│   ├── Assets.js       # Asset management
│   ├── ScanLauncher.js # Scan configuration
│   ├── Dashboard.js    # Scan results
│   ├── Vulnerabilities.js # Vuln management
│   └── Settings.js     # Configuration
├── hooks/              # Custom React hooks
│   └── useApi.js       # API integration hooks
├── utils/              # Utility functions
│   └── helpers.js      # Common helper functions
└── App.js              # Main application component
```

### API Integration
- RESTful API communication
- Custom hooks for data fetching
- Error handling and loading states
- Real-time updates for scan progress

## 🚀 Getting Started

### Prerequisites
- Node.js 16+ and npm
- React development environment

### Installation
```bash
cd frontend
npm install
```

### Development
```bash
npm start
```
Opens the application at `http://localhost:3000` (or next available port)

### Build for Production
```bash
npm run build
```

## 🔌 API Integration

The frontend expects a backend API with the following endpoints:

### Scans
- `GET /scans` - List all scans
- `POST /scans` - Create new scan
- `GET /scans/{id}` - Get scan details
- `POST /scans/{id}/stop` - Stop running scan

### Assets
- `GET /assets` - List all assets
- `POST /assets` - Create new asset
- `PUT /assets/{id}` - Update asset
- `DELETE /assets/{id}` - Delete asset

### Vulnerabilities
- `GET /vulnerabilities` - List vulnerabilities
- `PATCH /vulnerabilities/{id}` - Update vulnerability

## 🎯 Key Components

### Navigation Layout
- Responsive sidebar navigation
- Mobile-friendly drawer
- Active page highlighting
- Quick action shortcuts

### Data Tables
- Sortable columns
- Filtering capabilities
- Pagination support
- Export functionality

### Real-time Updates
- Progress tracking for scans
- Status indicators
- Auto-refresh capabilities
- Live activity feeds

### Form Components
- Validation and error handling
- Dynamic field updates
- Multi-step workflows
- Asset type-specific forms

## 🔒 Security Features

### Input Validation
- Client-side validation for all forms
- IP address and CIDR validation
- URL and domain name validation
- XSS prevention

### Access Control
- API key management
- Session handling
- Role-based permissions
- Audit logging

## 📱 Mobile Responsiveness

- Adaptive layout for different screen sizes
- Touch-friendly interface
- Mobile navigation patterns
- Optimized performance

## 🎨 Customization

### Theming
- Material-UI theme customization
- Dark/light mode support
- Custom color schemes
- Typography configuration

### Branding
- Logo and brand colors
- Custom styling
- White-label ready

## 🚀 Future Enhancements

### Planned Features
- Real-time notifications
- Advanced filtering and search
- Custom dashboard widgets
- Integration with more security tools
- Compliance reporting templates
- Team collaboration features

### Integration Roadmap
- More SIEM platforms
- Ticketing system integration
- SSO authentication
- Advanced analytics
- Machine learning insights

## 📖 Usage Guidelines

### Best Practices
1. **Asset Management**: Organize assets with meaningful names and tags
2. **Scan Planning**: Use appropriate profiles for different scan types
3. **Vulnerability Triage**: Prioritize by severity and impact
4. **Regular Updates**: Keep scan data current with periodic rescans
5. **Documentation**: Use notes fields for context and decisions

### Workflow Recommendations
1. **Initial Setup**: Configure assets and integrations
2. **Baseline Scanning**: Run comprehensive scans on all assets
3. **Regular Monitoring**: Schedule periodic scans
4. **Vulnerability Management**: Triage and track remediation
5. **Reporting**: Export data for compliance and reporting

This frontend provides a solid foundation for security professionals to manage their scanning operations efficiently while maintaining a user-friendly interface that scales from small teams to enterprise environments.
