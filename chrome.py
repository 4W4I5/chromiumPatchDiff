import re


class Chrome:
    # Holds Chrome version components and validates string input.
    _VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,3}$")

    def __init__(self, version: str = ""):
        """
        Chrome versions are usually in the format, AAA.BBB.CCC.DDD
        A -> Major version
        B -> Minor version
        C -> Build Number
        D -> Patch Number
        """
        self.major = 0
        self.minor = 0
        self.buildNumber = 0
        self.patchNumber = 0
        if version:
            self.setVersion(version)

    def setVersion(self, version: str):
        # Parse string
        cleaned = version.strip()
        if not self._VERSION_RE.fullmatch(cleaned):
            raise ValueError("Version must match A[.B[.C[.D]]] where all components are integers")

        parts = cleaned.split(".")

        # Set
        self.major = int(parts[0])
        self.minor = int(parts[1]) if len(parts) > 1 else 0
        self.buildNumber = int(parts[2]) if len(parts) > 2 else 0
        self.patchNumber = int(parts[3]) if len(parts) > 3 else 0

    def getMajorVersion(self):
        return self.major

    def getMinorVersion(self):
        return self.minor

    def getBuildNumber(self):
        return self.buildNumber

    def getPatchNumber(self):
        return self.patchNumber

    def getVersion(self):
        return f"{self.getMajorVersion()}.{self.getMinorVersion()}.{self.getBuildNumber()}.{self.getPatchNumber()}"

    def asTuple(self):
        return (
            self.getMajorVersion(),
            self.getMinorVersion(),
            self.getBuildNumber(),
            self.getPatchNumber(),
        )


if __name__ == "__main__":
    chrome = Chrome()
    chrome.setVersion("146.0.7680.178")
    print(f"Get chrome version -> {chrome.getVersion()}")
    print(f"Get main version -> {chrome.getMajorVersion()}")
    print(f"Get minor version -> {chrome.getMinorVersion()}")
    print(f"Get build version -> {chrome.getBuildNumber()}")
    print(f"Get patch version -> {chrome.getPatchNumber()}")
