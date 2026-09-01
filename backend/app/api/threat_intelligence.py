from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.security import require_analyst
from app.models.user import User
from app.database.session import get_db
from app.models.incident import Incident
from app.services.threat_intelligence_service import (
    ThreatIntelligenceService,
)
from app.services.ioc_extractor import IOCExtractor
from app.services.threat_intelligence_enrichment_service import (
    ThreatIntelligenceEnrichmentService,
)


router = APIRouter(
    prefix="/threat-intelligence",
    tags=["Threat Intelligence"],
)


# =========================================================
# SERVICES
# =========================================================

service = ThreatIntelligenceService()
ioc_extractor = IOCExtractor()
enrichment_service = ThreatIntelligenceEnrichmentService()


# =========================================================
# REQUEST SCHEMAS
# =========================================================

class TextAnalysisRequest(BaseModel):
    text: str


class URLAnalysisRequest(BaseModel):
    url: str


# =========================================================
# ABUSEIPDB - CHECK ONE IP
# =========================================================

@router.get("/ip/{ip_address}")
def check_ip(
    ip_address: str,
    current_user: User = Depends(require_analyst),
):
    try:
        return service.check_ip(
            ip_address
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# ABUSEIPDB - ANALYZE TEXT
# =========================================================

@router.post("/analyze")
def analyze_text(
    request: TextAnalysisRequest,
    current_user: User = Depends(require_analyst),
):
    try:
        return service.analyze_text(
            request.text
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# VIRUSTOTAL - CHECK IP
# =========================================================

@router.get("/virustotal/ip/{ip_address}")
def virustotal_check_ip(
    ip_address: str,
    current_user: User = Depends(require_analyst),
):
    try:
        return enrichment_service.virustotal.check_ip(
            ip_address
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# VIRUSTOTAL - CHECK DOMAIN
# =========================================================

@router.get("/virustotal/domain/{domain}")
def virustotal_check_domain(
    domain: str,
    current_user: User = Depends(require_analyst),
):
    try:
        return enrichment_service.virustotal.check_domain(
            domain
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# VIRUSTOTAL - CHECK URL
# =========================================================

@router.post("/virustotal/url")
def virustotal_check_url(
    request: URLAnalysisRequest,
    current_user: User = Depends(require_analyst),
):
    try:
        return enrichment_service.virustotal.check_url(
            request.url
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# VIRUSTOTAL - CHECK HASH
# =========================================================

@router.get("/virustotal/hash/{file_hash}")
def virustotal_check_hash(
    file_hash: str,
    current_user: User = Depends(require_analyst),
):
    try:
        return enrichment_service.virustotal.check_hash(
            file_hash
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# OTX - CHECK IP
# =========================================================

@router.get("/otx/ip/{ip_address}")
def otx_check_ip(
    ip_address: str,
    current_user: User = Depends(require_analyst),
):
    try:
        return enrichment_service.otx.check_ip(
            ip_address
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# OTX - CHECK DOMAIN
# =========================================================

@router.get("/otx/domain/{domain}")
def otx_check_domain(
    domain: str,
    current_user: User = Depends(require_analyst),
):
    try:
        return enrichment_service.otx.check_domain(
            domain
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# OTX - CHECK URL
# =========================================================

@router.post("/otx/url")
def otx_check_url(
    request: URLAnalysisRequest,
    current_user: User = Depends(require_analyst),
):
    try:
        return enrichment_service.otx.check_url(
            request.url
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# OTX - CHECK HASH
# =========================================================

@router.get("/otx/hash/{file_hash}")
def otx_check_hash(
    file_hash: str,
    current_user: User = Depends(require_analyst),
):
    try:
        return enrichment_service.otx.check_hash(
            file_hash
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# ANALYZE INCIDENT - MULTI PROVIDER
# =========================================================

@router.get("/incident/{incident_id}")
def analyze_incident_threat_intelligence(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Extract and enrich Indicators of Compromise from an incident.

    Supported IOC types:
    - IP addresses
    - Domains
    - URLs
    - File hashes

    Providers:
    - AbuseIPDB
    - VirusTotal
    - AlienVault OTX
    - MISP
    """

    # =====================================================
    # 1. LOAD INCIDENT
    # =====================================================

    incident = (
        db.query(Incident)
        .filter(
            Incident.id == incident_id
        )
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    # =====================================================
    # 2. BUILD INCIDENT TEXT
    # =====================================================

    text = (
        f"{incident.title or ''} "
        f"{incident.description or ''}"
    )

    # =====================================================
    # 3. EXTRACT IOCs
    # =====================================================

    try:
        extracted = ioc_extractor.extract_all(
            text
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "IOC extraction failed: "
                f"{str(exc)}"
            ),
        )

    # -----------------------------------------------------
    # IP addresses
    # -----------------------------------------------------

    ips = set(
        extracted.get(
            "ips",
            [],
        )
    )

    if incident.source_ip:
        ips.add(
            incident.source_ip
        )

    if incident.destination_ip:
        ips.add(
            incident.destination_ip
        )

    # -----------------------------------------------------
    # Domains
    # -----------------------------------------------------

    domains = set(
        extracted.get(
            "domains",
            [],
        )
    )

    # -----------------------------------------------------
    # URLs
    # -----------------------------------------------------

    urls = set(
        extracted.get(
            "urls",
            [],
        )
    )

    # -----------------------------------------------------
    # Hashes
    # -----------------------------------------------------

    hashes = extracted.get(
        "hashes",
        [],
    )

    results = []

    # =====================================================
    # 4. IP ENRICHMENT
    # =====================================================

    for ip_address in sorted(
        ips
    ):
        result = enrichment_service.enrich_ip(
            ip_address
        )

        results.append(
            result
        )

    # =====================================================
    # 5. DOMAIN ENRICHMENT
    # =====================================================

    for domain in sorted(
        domains
    ):
        result = enrichment_service.enrich_domain(
            domain
        )

        results.append(
            result
        )

    # =====================================================
    # 6. URL ENRICHMENT
    # =====================================================

    for url in sorted(
        urls
    ):
        result = enrichment_service.enrich_url(
            url
        )

        results.append(
            result
        )

    # =====================================================
    # 7. HASH ENRICHMENT
    # =====================================================

    for hash_data in hashes:

        if not isinstance(
            hash_data,
            dict,
        ):
            continue

        file_hash = hash_data.get(
            "value"
        )

        hash_type = hash_data.get(
            "hash_type"
        )

        if not file_hash:
            continue

        result = enrichment_service.enrich_hash(
            file_hash,
            hash_type=hash_type,
        )

        results.append(
            result
        )

    # =====================================================
    # 8. RESPONSE
    # =====================================================

    return {
        "incident_id": incident.id,
        "source": incident.source,
        "source_ip": incident.source_ip,
        "destination_ip": incident.destination_ip,

        "extracted_iocs": {
            "ips": sorted(
                ips
            ),
            "domains": sorted(
                domains
            ),
            "urls": sorted(
                urls
            ),
            "hashes": hashes,
        },

        "ioc_summary": {
            "ips": len(
                ips
            ),
            "domains": len(
                domains
            ),
            "urls": len(
                urls
            ),
            "hashes": len(
                hashes
            ),
        },

        "ioc_count": len(
            results
        ),

        "threat_intelligence": results,
    }