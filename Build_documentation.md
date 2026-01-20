# Build Documentation

## Prerequisites

Install Java 17:

```bash
sudo apt update
sudo apt install -y openjdk-17-jdk
```

## Install sbt

Add the sbt repository and key:

```bash
echo "deb https://repo.scala-sbt.org/scalasbt/debian all main" | sudo tee /etc/apt/sources.list.d/sbt.list
echo "deb https://repo.scala-sbt.org/scalasbt/debian /" | sudo tee /etc/apt/sources.list.d/sbt_old.list
curl -sL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x2EE0EA64E40A89B84B2DF73499E82A75642AC823" | sudo tee /etc/apt/trusted.gpg.d/sbt.asc
```

Install sbt:

```bash
sudo apt-get update
sudo apt-get install sbt
```

Verify installation:

```bash
sbt --version
```

## Build

Compile the project:

```bash
sbt compile
```
