
#  Secure Web Application – AppSec-project

##  Description

A secure login/registeration web page developed as part of the **Application Security and Secure Code** course.  
This app demonstrates secure coding practices including:

- Authentication and Authorization
- Input Validation and Sanitization
- Encryption and Password Hashing
- Session Management
- Threat Modeling and Risk Assessment
- Code Security Scanning

---

## Tech Stack

- **Frontend:** [ HTML-CSS ]
- **Backend:** Node.js + Express
- **Database:** MongoDB
- **Authentication:** session-based + bcrypt
- **Deployment:** [Render]


##  Features

- User registration and login
- Password hashing using `bcrypt`
- Input validation using `validator.js`
- Output sanitization using `DOMPurify`
- AES encryption for sensitive data
- Role-based access control (Admin / User)
- Session management with secure cookies
- Rate limiting and CAPTCHA protection
- STRIDE threat modeling
- DREAD risk assessment
- Security headers using `helmet `
- CORS policy and secure coding practices
- Code scanning using industry tools



 ## Security Implementations

| Category               | Implementation                                  
|------------------------|-------------------------------------------------
| Authentication         | session-based     
| Authorization          | Role-based access control                       
| Hashing & Encryption   | bcrypt & AES for sensitive fields                                                                
| Input Validation       | validator.js                                    
| Output Sanitization    | DOMPurify                                       
| Session Management     | JWT expiry , secure cookies    
| Rate Limiting          | express-rate-limit                              
| CAPTCHA                | Google reCAPTCHA (on login/registration forms)  
| CORS                   | Configured using `cors` module                  
| Headers                | Helmet for CSP, XSS protection


##  Threat Modeling

- [STRIDE Threat Model](docs/STRIDE.md)
- [DREAD Risk Assessment](docs/DREAD.md)

##  Code Scanning Tools

Security tools used to scan and test the codebase:
- [ ] GitHub CodeQL


## Deployment
Link: https://appsec-project-4y5q.onrender.com/
Instructions:
```bash

# clone project
git clone https://github.com/amjad-altarefe/AppSec-project.git
cd project

# install dependencies
  npm install
  
# run app
  node server.js
  npm start
```
======
#  Secure Web Application – AppSec-project

##  Description

A secure login/registeration web page developed as part of the **Application Security and Secure Code** course.  
This app demonstrates secure coding practices including:

- Authentication and Authorization
- Input Validation and Sanitization
- Encryption and Password Hashing
- Session Management
- Threat Modeling and Risk Assessment
- Code Security Scanning

---

## Tech Stack

- **Frontend:** [ HTML-CSS ]
- **Backend:** Node.js + Express
- **Database:** MongoDB
- **Authentication:** session-based + bcrypt
- **Deployment:** [Render]


##  Features

- User registration and login
- Password hashing using `bcrypt`
- Input validation using `validator.js`
- Output sanitization using `DOMPurify`
- AES encryption for sensitive data
- Role-based access control (Admin / User)
- Session management with secure cookies
- Rate limiting and CAPTCHA protection
- STRIDE threat modeling
- DREAD risk assessment
- Security headers using `helmet `
- CORS policy and secure coding practices
- Code scanning using industry tools



 ## Security Implementations

| Category               | Implementation                                  
|------------------------|-------------------------------------------------
| Authentication         | session-based     
| Authorization          | Role-based access control                       
| Hashing & Encryption   | bcrypt & AES for sensitive fields                                                                
| Input Validation       | validator.js                                    
| Output Sanitization    | DOMPurify                                       
| Session Management     | JWT expiry , secure cookies    
| Rate Limiting          | express-rate-limit                              
| CAPTCHA                | Google reCAPTCHA (on login/registration forms)  
| CORS                   | Configured using `cors` module                  
| Headers                | Helmet for CSP, XSS protection


##  Threat Modeling

- [STRIDE Threat Model](docs/STRIDE.md)
- [DREAD Risk Assessment](docs/DREAD.md)

##  Code Scanning Tools

Security tools used to scan and test the codebase:
- [ ] GitHub CodeQL


## Deployment
Link: https://appsec-project-4y5q.onrender.com/
Instructions:
```bash

# clone project
git clone https://github.com/amjad-altarefe/AppSec-project.git
cd project

# install dependencies
  npm install
  
# run app
  node server.js
  npm start
```
