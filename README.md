# E-Commerce Application - SonarCloud Workshop

Eine Spring Boot E-Commerce Anwendung für SonarCloud Quality & Security Workshop.

## 📋 Voraussetzungen

### System Requirements
- **JDK**: 11 oder höher
- **Maven**: 3.6+ ([Download](https://maven.apache.org/download.cgi))
- **Git**: Optional, für Version Control
- **IDE**: IntelliJ IDEA (Community oder Ultimate)
- **SonarQube for IDE Plugin**: Für Live-Feedback während des Codens

### Kompatibilität
✅ **Windows** (10, 11)  
✅ **macOS** (10.15+)  
✅ **Linux** (Ubuntu, Debian, Fedora, etc.)

### Überprüfung der Installation

```bash
# Java Version prüfen
java -version
# Sollte zeigen: openjdk version "11.x.x" oder höher

# Maven Version prüfen
mvn -version
# Sollte zeigen: Apache Maven 3.6.x oder höher
```

### IntelliJ IDEA Setup

#### 1. IntelliJ IDEA installieren

**Download:** [https://www.jetbrains.com/idea/download/](https://www.jetbrains.com/idea/download/)

- **Community Edition**: Kostenlos, ausreichend für den Workshop
- **Ultimate Edition**: 30-Tage Trial, empfohlen für alle Features

#### 2. SonarQube for IDE Plugin installieren

**Wichtig:** Dieses Plugin zeigt Issues direkt in IntelliJ an - noch vor dem SonarCloud Scan!

**Installation:**

1. IntelliJ öffnen
2. **Windows/Linux**: `File` → `Settings` → `Plugins`  
   **macOS**: `IntelliJ IDEA` → `Settings` → `Plugins`
3. Suche nach: **"SonarQube for IDE"** (früher SonarLint)
4. Click **Install**
5. IntelliJ neu starten

**Alternativ:** [Marketplace Link](https://plugins.jetbrains.com/plugin/7973-sonarlint)

**📖 Detaillierte Anleitung:** Siehe [INTELLIJ_SETUP.md](INTELLIJ_SETUP.md) für Schritt-für-Schritt Anleitung mit Screenshots-Beschreibung.

#### 3. Plugin mit SonarCloud verbinden (Optional für später)

Nach dem SonarCloud Scan kannst du das Plugin verbinden:

1. **Settings** → **Tools** → **SonarQube for IDE** → **SonarCloud**
2. Click **Add**
3. Token von SonarCloud einfügen
4. Organisation auswählen
5. Projekt binden

**Vorteil:** Siehst Issues während du tippst + SonarCloud Rules!

## 🚀 Quick Start

### 1. Projekt Setup

```bash
# Verzeichnis wechseln
cd ecommerce-app

# Dependencies installieren
mvn clean install
```

### 2. Anwendung starten

```bash
# Starten
mvn spring-boot:run

# Warte bis du diese Meldung siehst:
# "Started Application in X.XXX seconds"
```

### 3. Testen

Öffne Browser oder nutze curl:

```bash
# Alle Orders ansehen
curl http://localhost:8080/api/orders

# Alle Users ansehen
curl http://localhost:8080/api/users
```

## 📡 API Endpoints

### Users
```
GET    /api/users              - Alle User
GET    /api/users/{id}         - User by ID  
GET    /api/users/search       - User suchen (?email=alice)
POST   /api/users              - User erstellen
```

### Orders
```
GET    /api/orders             - Alle Orders
GET    /api/orders/{id}        - Order by ID
GET    /api/orders/user/{id}   - Orders eines Users
GET    /api/orders/search      - Orders suchen (?product=MacBook)
POST   /api/orders             - Order erstellen
PUT    /api/orders/{id}/status - Status ändern (?status=DELIVERED)
GET    /api/orders/stats/{id}  - User Statistiken
```

### Database Console
```
GET    /h2-console             - H2 Database Console
       JDBC URL: jdbc:h2:mem:testdb
       Username: sa
       Password: (leer lassen)
```

## 🗄️ Demo-Daten

Die Anwendung startet automatisch mit:

### 3 Users:
- **Alice** (alice@example.com) - Premium User, 2 Orders, €4,407
- **Bob** (bob@example.com) - Regular User, 2 Orders, €1,736
- **Charlie** (charlie@example.com) - New User, 1 Order, €139

### 5 Orders:
- MacBook Pro 16" (€2,249)
- 2x iPhone 15 Pro (€2,158)
- Samsung Galaxy S24 (€899)
- 3x AirPods Pro (€837)
- Kindle Paperwhite (€139)

**Total Revenue**: €6,282

## 💡 SonarQube for IDE - Live Feedback

**Bevor du SonarCloud nutzt**, kannst du Issues schon in IntelliJ sehen!

### Live-Analyse während du codest

SonarQube for IDE zeigt Issues in Echtzeit:

1. **Öffne Projekt in IntelliJ**
   ```bash
   # Im Projekt-Verzeichnis
   idea .
   # oder IntelliJ öffnen und Projekt importieren
   ```

2. **Warte auf Indexierung**
   - IntelliJ muss das Projekt erst laden
   - Unten rechts: "Indexing..." sollte verschwinden

3. **Öffne eine Java-Datei**
   - z.B. `UserService.java`
   - Issues werden automatisch markiert

4. **Issues ansehen**
   - **Gelbe/Rote Wellenlinien** im Code
   - **Glühbirne-Icon** → Click für Details
   - **SonarQube Tab** unten → Alle Issues

### Was siehst du sofort?

Ohne SonarCloud-Scan zeigt das Plugin bereits:

✅ **Code Smells**: Komplexität, Magic Numbers, etc.  
✅ **Bugs**: NullPointer, Resource Leaks, etc.  
✅ **Security Hotspots**: SQL Injection, Hardcoded Credentials  
⚠️ **CVEs**: Werden erst bei SonarCloud Scan erkannt (braucht Dependency-Analyse)

### Beispiel

Öffne `UserService.java` Line 50:

```java
String query = "SELECT * FROM users WHERE email LIKE '%" + email + "%'";
```

SonarQube for IDE zeigt:
- 🔴 **Critical**: SQL Injection vulnerability
- 💡 **Fix**: Use PreparedStatement instead

### Vorteile

| Feature | SonarQube for IDE | SonarCloud |
|---------|-------------------|------------|
| **Speed** | Instant | 2-3 Min Scan |
| **Local** | Ja, offline | Nein, braucht Internet |
| **CVEs** | ❌ | ✅ |
| **Team Rules** | Nach Binding | ✅ |
| **History** | ❌ | ✅ |
| **CI/CD** | ❌ | ✅ |

**Best Practice:** Nutze beide zusammen!
- IntelliJ Plugin: Während Entwicklung
- SonarCloud: Für Team, CI/CD, CVEs

## 🔍 SonarCloud Scan

### SonarCloud Account erstellen

1. Gehe zu [sonarcloud.io](https://sonarcloud.io)
2. "Start Free" → Mit GitHub/GitLab anmelden
3. "Start your free trial" → **Team Plan** wählen (14 Tage kostenlos)
4. Organisation erstellen

### Projekt analysieren

```bash
mvn clean verify sonar:sonar \
  -Dsonar.projectKey=YOUR_PROJECT_KEY \
  -Dsonar.organization=YOUR_ORG \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.token=YOUR_TOKEN
```

**Token generieren:**
1. SonarCloud → My Account → Security
2. Generate Token
3. Token kopieren und im Befehl einfügen

## 📊 Was SonarCloud finden wird

SonarCloud Team wird automatisch erkennen:

- **6+ CVEs** in Dependencies (Log4Shell, Jackson, etc.)
- **15+ Security Hotspots** (SQL Injection, Hardcoded Credentials, etc.)
- **20+ Bugs** (NullPointer, Resource Leaks, etc.)
- **70+ Code Smells** (Complexity, Duplication, Magic Numbers, etc.)

**Total**: 100+ Issues

## 🛠️ Troubleshooting

### Port 8080 bereits belegt

```bash
# Windows: Finde Prozess
netstat -ano | findstr :8080

# Mac/Linux: Finde Prozess
lsof -i :8080

# Anderen Port nutzen
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8081
```

### "JAVA_HOME not set"

```bash
# Windows
set JAVA_HOME=C:\Program Files\Java\jdk-11

# Mac/Linux
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk
```

### Maven Build Fehler

```bash
# Cache löschen
mvn clean

# Offline-Modus deaktivieren
mvn clean install -U
```

### H2 Console lädt nicht

Prüfe `src/main/resources/application.properties`:
```properties
spring.h2.console.enabled=true
```

## 💡 Tipps für den Workshop

### Für Teilnehmer

1. **Vor dem Workshop**: 
   - JDK 11 installieren
   - Maven installieren
   - SonarCloud Account erstellen
   
2. **Während des Workshops**:
   - Anwendung lokal laufen lassen
   - API Endpoints testen
   - SonarCloud Dashboard erkunden

3. **Nach dem Workshop**:
   - Issues selbst fixen
   - Re-Scan durchführen
   - Improvements dokumentieren

### Für Trainer

- Alle Issues sind sorgfältig platziert
- Business Logic ist einfach gehalten
- Code kompiliert und läuft problemlos
- Demo-Daten sind aussagekräftig
- Siehe `TRAINER_GUIDE.md` für Issue-Übersicht

## 📂 Projekt-Struktur

```
ecommerce-app/
├── pom.xml                          # Maven Dependencies
├── src/
│   ├── main/
│   │   ├── java/com/example/ecommerce/
│   │   │   ├── Application.java                # Main
│   │   │   ├── controller/
│   │   │   │   ├── UserController.java         # User API
│   │   │   │   └── OrderController.java        # Order API
│   │   │   ├── service/
│   │   │   │   ├── UserService.java            # Business Logic
│   │   │   │   └── OrderService.java
│   │   │   ├── repository/
│   │   │   │   ├── UserRepository.java         # Data Access
│   │   │   │   └── OrderRepository.java
│   │   │   └── model/
│   │   │       ├── User.java                   # Entity
│   │   │       ├── Order.java
│   │   │       └── OrderStatus.java            # Enum
│   │   └── resources/
│   │       └── application.properties
│   └── test/
│       └── java/                               # (Tests können hinzugefügt werden)
└── README.md                                   # Diese Datei
```

## 🎯 Lernziele

Nach diesem Workshop können Sie:

✅ SonarCloud Team einrichten und nutzen  
✅ CVEs in Dependencies erkennen  
✅ Security Hotspots identifizieren  
✅ Code Quality Metriken interpretieren  
✅ Technical Debt verstehen  
✅ Quality Gates konfigurieren  
✅ Issues systematisch beheben  

## 📚 Weiterführende Links

- [SonarCloud Dokumentation](https://docs.sonarcloud.io)
- [Spring Boot Docs](https://docs.spring.io/spring-boot/docs/current/reference/html/)
- [Maven Guide](https://maven.apache.org/guides/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## ⚖️ Lizenz

Nur für Bildungszwecke. Nicht für Produktions-Einsatz!

---

**Viel Erfolg beim Workshop! 🎓**
