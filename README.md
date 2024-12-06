# Cybether - Cybersecurity Dashboard

A Governance, Risk, and Compliance (GRC) dashboard built with React and Flask, designed to help organizations manage their cybersecurity posture effectively.

## Features

- **Threat Level Monitoring**: Track and update current threat levels with detailed descriptions
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
git clone https://github.com/YOUR_USERNAME/cybether.git
cd cybether
```

2. Start the application using Docker Compose:
```bash
docker compose up --build
```

3. Access the application:
- Frontend: http://localhost:3000
- Backend API: http://localhost:5001
- Default admin credentials:
  - Username: admin
  - Password: admin123

## Development Setup

### Frontend (React)

```bash
cd frontend
npm install
npm start
```

### Backend (Flask)

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
flask run
```

### Database (PostgreSQL)

The application uses PostgreSQL, which is automatically set up through Docker Compose. For local development, you'll need to:

1. Install PostgreSQL
2. Create a database named 'grc_dashboard'
3. Update the database connection string in `config.py`

## Environment Variables

Create a `.env` file in the root directory:

```env
FLASK_APP=app.py
FLASK_ENV=development
DATABASE_URL=postgresql://postgres:postgres@db:5432/grc_dashboard
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here
CORS_ORIGINS=http://localhost:3000
```

## Contributing

1. Fork the repository
2. Create a new branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add new feature'`)
5. Push to the branch (`git push origin feature/improvement`)
6. Create a Pull Request

## Security

This project includes security features but should be properly audited and hardened before use in a production environment. Key considerations:

- Change default admin credentials
- Use strong secret keys
- Enable HTTPS
- Regular security updates
- Proper access control implementation
- Security headers configuration

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- React.js community
- Flask community
- Tailwind CSS team
- All contributors and supporters

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.

---

Made with ❤️ by [YOUR_NAME]