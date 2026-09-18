# WebShield- Hybrid Phishing Detection & URL Risk Analysis System

WebShield is a hybrid cybersecurity system designed to detect and analyze potentially malicious websites in real time.

It combines machine learning, URL structural analysis, webpage analysis, domain intelligence, and infrastructure investigation to generate an explainable risk score for a website.

## Features

- Real-time URL phishing detection
- Machine learning-based URL classification
- URL structural analysis
- Domain risk analysis
- Webpage structural analysis
- Hybrid risk scoring
- Explainable detection reasons
- Chrome browser extension
- Flask REST API backend
- Streamlit Security Operations dashboard
- IP geolocation and ASN intelligence
- Hosting organization information
- RDAP domain registration intelligence
- Domain age and nameserver information
- Threat history and analytics
- Infrastructure visualization

## System Architecture

                    Website / URL
                         |
                         v
              Chrome Extension
                         |
                         v
                  Flask Backend
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
     ML Detection   URL Analysis   Page Analysis
          |              |              |
          +--------------+--------------+
                         |
                         v
                  Domain Analysis
                         |
                         v
                 Hybrid Risk Engine
                         |
                         v
                  Final Risk Score
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
       SAFE        SUSPICIOUS       HIGH RISK
                         |
                         v
                Security Dashboard
                         |
                         v
              Infrastructure Intelligence
              IP / ASN / Country / RDAP
