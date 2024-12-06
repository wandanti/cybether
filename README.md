# Cybether - Cybersecurity Dashboard

A simple Governance, Risk, and Compliance (GRC) dashboard built with React and Flask.

## Features

- **Threat Level Monitoring**: Track and update current threat levels with descriptions
- **Maturity Rating**: Monitor security maturity levels with trend analysis
- **Risk Management**: Track and manage security risks with severity levels
- **Project Tracking**: Monitor security project progress and completion
- **Compliance Framework**: Track compliance with multiple frameworks (PCI DSS, NIST CSF, ISO 27001, SOC 2)
- **Admin Interface**: Secure admin interface for data management
- **Authentication**: JWT-based authentication system

## Technology Stack

- **Frontend**: React.js with Tailwind CSS
- **Backend**: Python Flask
- **Database**: PostgreSQL
- **Authentication**: JWT (JSON Web Tokens)
- **Containerization**: Docker & Docker Compose

## Prerequisites

- Docker and Docker Compose installed
- Git installed
- Node.js v18+ (for local development)
- Python 3.11+ (for local development)

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/wandanti/cybether.git
cd cybether
```

2. Start the application using Docker Compose:
```bash
docker compose up --build
```

3. Access the application:
- Frontend: http://localhost:3000
- Admin Interface: http://localhost:3000/admin
- Backend API: http://localhost:5001
- Default admin credentials:
  - Username: admin
  - Password: admin123

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support or inquiries, please contact Jean Carlos (JC) via LinkedIn at https://www.linkedin.com/in/jeanpc/

---

Made with ❤️ by JC