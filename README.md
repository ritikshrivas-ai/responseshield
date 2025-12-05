# ResponseShield: Advanced SOC Incident Response Platform

## Overview
**ResponseShield** is a comprehensive Security Operations Center (SOC) incident response platform built for modern cybersecurity teams. It integrates MITRE ATT&CK framework, threat intelligence, automated response workflows, and security tools into a unified interface for efficient incident management.

**Version:** 1.0  
**Author:** Ritik Shrivas  
**Email:** ritikshrivas.ai@gmail.com  
**Git Repository:** https://github.com/ritikshrivas-ai/responseshield  

## Features

### 🚀 Core Capabilities
- **Real-time Dashboard:** Live monitoring with threat activity timelines and attack vector analysis
- **MITRE ATT&CK Integration:** Full mapping of incidents to MITRE tactics and techniques
- **Automated Playbooks:** Pre-defined response workflows for common attack types
- **Threat Intelligence Hub:** IOC management with live threat feeds
- **Integrated Security Tools:** Built-in tools (Nmap, TCPdump, ClamAV, etc.)
- **WebSocket Notifications:** Real-time alerts and updates

### 🔧 Technical Features
- **Flask-based Web Interface:** Modern, responsive UI with dark theme
- **SocketIO Integration:** Real-time bidirectional communication
- **Chart Visualization:** Plotly.js for interactive charts and graphs
- **Background Monitoring:** Continuous threat detection and system health checks
- **Simulated Mode:** Demo-friendly with simulated tool outputs
- **Production Ready:** Error handling and logging implemented

### 📊 SOC Metrics
- Mean Time to Detect (MTTD) tracking
- Mean Time to Respond (MTTR) monitoring
- False positive rate analysis
- Incident severity classification
- Response time targets

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Basic security tools (optional, for real execution)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/ritikshrivas-ai/responseshield.git
cd responseshield

# Install dependencies
pip install flask flask-socketio plotly pandas numpy pyyaml psutil

# Run the platform
python response.py
```

### Docker Support (Coming Soon)
```bash
# Future release will include Docker support
docker build -t responseshield .
docker run -p 5000:5000 responseshield
```

## Usage

### Accessing the Platform
1. Start the application: `python soc_platform.py`
2. Open browser: `http://localhost:5000`
3. Default interface: Dark-themed SOC dashboard

### Key Sections

#### 1. Dashboard
- Real-time incident monitoring
- System health metrics
- Threat activity visualization
- Recent incidents with severity badges

#### 2. Incident Response Center
- MITRE ATT&CK based workflows
- Phishing, ransomware, data exfiltration playbooks
- Step-by-step response procedures
- Incident documentation and tracking

#### 3. Threat Intelligence Hub
- IOC (Indicator of Compromise) management
- Live threat feeds
- IOC search and analysis
- Threat database with severity assessment

#### 4. Security Tools
- Integrated Kali Linux tools
- Network scanning (Nmap)
- Packet analysis (TCPdump)
- Malware scanning (ClamAV)
- System monitoring tools

#### 5. Reports & Analytics
- Incident statistics
- Response time analysis
- Report generation (daily/weekly/monthly)
- Performance metrics

## API Endpoints

### Incident Management
- `GET /api/incidents` - Get recent incidents
- `POST /api/incidents/create` - Create new incident
- `GET /api/incidents/<incident_id>` - Get specific incident
- `POST /api/incidents/update` - Update incident details
- `POST /api/incidents/resolve` - Mark incident as resolved

### Threat Intelligence
- `GET /api/threats/latest` - Get latest threats
- `GET /api/threats/search` - Search IOC database
- `POST /api/threats/add` - Add new IOC
- `POST /api/threats/block` - Block IOC
- `POST /api/threats/remove` - Remove IOC

### System Tools
- `GET /api/system/health` - Get system health metrics
- `GET /api/network/scan` - Perform network scan
- `POST /api/tools/run` - Execute security tool

### Reports
- `GET /api/reports/stats` - Get report statistics
- `POST /api/reports/generate` - Generate reports

### Key Components
- **AdvancedSOCMonitor:** Core monitoring engine
- **SOC_PLAYBOOKS:** Response workflows for different incident types
- **MITRE_TACTICS:** MITRE ATT&CK framework mapping
- **WebSocket Handlers:** Real-time communication
- **Background Monitoring:** Continuous threat detection

## Configuration

### Environment Variables (Future Release)
```bash
SOC_SECRET_KEY=your_secret_key
SOC_DATABASE_URL=postgresql://user:pass@localhost/soc_db
SOC_THREAT_FEEDS=abuse_ch,alien_vault,openphish
```

### Customizing Playbooks
Edit the `SOC_PLAYBOOKS` dictionary in the code to:
- Add new incident types
- Modify response steps
- Update tool integrations
- Adjust severity thresholds

## Integration Points

### SIEM Integration
- Splunk, QRadar, Elasticsearch (via API)
- Syslog forwarding capability
- Custom alert ingestion

### EDR Integration
- CrowdStrike, Carbon Black, SentinelOne
- Endpoint isolation commands
- Process termination

### Network Security
- Cisco, Palo Alto, Fortinet firewall rules
- DNS blocking
- Proxy filtering

## Development

### Adding New Features
1. Fork the repository
2. Create a feature branch
3. Implement changes with proper testing
4. Submit pull request

### Testing
```bash
# Run with debug mode
python soc_platform.py --debug

# Test API endpoints
curl http://localhost:5000/api/incidents
curl -X POST http://localhost:5000/api/incidents/create -H "Content-Type: application/json" -d '{"type":"Test","severity":"low"}'
```

### Code Style
- Follow PEP 8 guidelines
- Use descriptive variable names
- Add comments for complex logic
- Include error handling

## Security Considerations

### Best Practices
1. **Change Default Credentials:** Update SECRET_KEY in production
2. **Enable HTTPS:** Use reverse proxy with SSL termination
3. **Network Segmentation:** Deploy in isolated SOC network
4. **Access Control:** Implement role-based access (future release)
5. **Logging:** Monitor application logs for anomalies

### Data Protection
- IOC database stored in memory (persistent storage in future)
- Incident data includes PII considerations
- Export/import functionality for threat intel

## Performance

### System Requirements
- Minimum: 2GB RAM, 2 CPU cores, 10GB disk space
- Recommended: 8GB RAM, 4 CPU cores, 50GB disk space
- Supports 100+ concurrent incidents
- Handles 1000+ IOC database entries

### Optimization
- Background monitoring runs every 10 seconds
- WebSocket for real-time updates
- Chart data cached for performance
- Database pagination for large datasets

## Troubleshooting

### Common Issues

1. **Port 5000 already in use:**
   ```bash
   kill $(lsof -t -i:5000)
   # or
   python soc_platform.py --port 5001
   ```

2. **Missing dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **WebSocket connection issues:**
   - Check firewall settings
   - Verify browser supports WebSocket
   - Check console for errors

4. **Tool execution failures:**
   - Tools run in simulated mode by default
   - Install actual tools for real execution
   - Check tool paths and permissions

### Logs
- Application logs: `soc_platform.log`
- Access logs: Console output
- Error tracking: Python traceback in logs

## Roadmap

### Version 1.1 (Planned)
- [ ] Database persistence (SQLite/PostgreSQL)
- [ ] User authentication and RBAC
- [ ] SIEM API integrations
- [ ] Custom report templates
- [ ] Docker containerization

### Version 2.0 (Future)
- [ ] Multi-tenant architecture
- [ ] Mobile responsive design
- [ ] API key management
- [ ] Advanced analytics
- [ ] Machine learning integration

## Contributing

We welcome contributions! Please:
1. Check existing issues or create new ones
2. Fork the repository
3. Create a feature branch
4. Add tests for new functionality
5. Ensure code quality and documentation
6. Submit pull request

### Development Setup
```bash
git clone https://github.com/ritikshrivas-ai/responseshield.git
cd responseshield
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, issues, or feature requests:
- Create an issue on GitHub: [https://github.com/ritikshrivas-ai/responseshield/issues](https://github.com/ritikshrivas-ai/responseshield/issues)
- Email: ritikshrivas.ai@gmail.com

## Acknowledgments

- MITRE for the ATT&CK framework
- Open source security community
- Contributors and testers
- Cybersecurity professionals worldwide

---

**Disclaimer:** This tool is for educational and professional cybersecurity use only. Use responsibly and in compliance with all applicable laws and regulations. The authors are not responsible for misuse or damage caused by this software.

**Last Updated:** December 2025
