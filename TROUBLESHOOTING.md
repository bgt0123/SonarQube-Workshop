## 🛠️ Troubleshooting

### Port 8080 bereits belegt

```bash
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
# Cache löschen und neu bauen
mvn clean install -U
```