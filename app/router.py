from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.audit.service import audit
from app.auth.service import AuthService
from app.config import get_settings
from app.core.vault_service import VaultService
from app.core.vault_state import vault_state
from app.database import get_db
from app.dependencies import Principal, current_principal
from app.exceptions import AppError, ok
from app.kv.service import KVService
from app.schemas import (CreateKeyRequest, CreateSigningKeyRequest, DecryptRequest, EncryptRequest,
                         InitRequest, KVWriteRequest, LoginRequest, RegisterRequest, SignRequest,
                         UnlockRequest, VerifyRequest)
from app.transit.service import TransitService

router = APIRouter(prefix="/api/v1")


@router.post("/vault/init", tags=["Vault"], summary="Initialize the vault")
async def vault_init(body: InitRequest, db: Session = Depends(get_db)):
    return ok(VaultService(db, vault_state).init(body.master_passphrase, body.confirm_master_passphrase), 201)


@router.post("/vault/unlock", tags=["Vault"], summary="Unlock the vault")
async def vault_unlock(body: UnlockRequest, db: Session = Depends(get_db)):
    return ok(VaultService(db, vault_state).unlock(body.master_passphrase))


@router.post("/vault/lock", tags=["Vault"], summary="Lock the vault")
async def vault_lock():
    vault_state.lock(); return ok({"status": "locked"})


@router.get("/vault/status", tags=["Vault"], summary="Get vault status")
async def vault_status(db: Session = Depends(get_db)):
    return ok(VaultService(db, vault_state).status())


@router.post("/auth/register", tags=["Authentication"], summary="Register a user")
async def register(body: RegisterRequest, db: Session = Depends(get_db)):
    return ok(AuthService(db, get_settings()).register(str(body.email), body.passphrase, body.confirm_passphrase), 201)


@router.post("/auth/login", tags=["Authentication"], summary="Create a session")
async def login(body: LoginRequest, db: Session = Depends(get_db)):
    return ok(AuthService(db, get_settings()).login(str(body.email), body.passphrase))


@router.post("/auth/logout", tags=["Authentication"], summary="Revoke current session")
async def logout(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    AuthService(db, get_settings()).logout(p.session); return ok({"logged_out": True})


@router.get("/auth/me", tags=["Authentication"], summary="Get current user")
async def me(p: Principal = Depends(current_principal)):
    return ok({"email": p.user.email})


def denied_audit(db: Session, request: Request, p: Principal, action: str,
                 resource_type: str, identifier: str, exc: AppError) -> None:
    if exc.code == "PERMISSION_DENIED":
        audit(db, p.user.email, action, resource_type, identifier, "DENIED",
              request.client.host if request.client else None)


@router.get("/kv", tags=["KV Engine"], summary="List secret metadata")
async def kv_list(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return ok(KVService(db, vault_state).list(p.user.email))


@router.put("/kv/{path:path}", tags=["KV Engine"], summary="Create or update an encrypted secret")
async def kv_write(path: str, body: KVWriteRequest, request: Request,
             p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    try: return ok(KVService(db, vault_state).write(path, p.user.email, body.data))
    except AppError as exc: denied_audit(db, request, p, "WRITE", "KV_SECRET", path, exc); raise


@router.get("/kv/{path:path}", tags=["KV Engine"], summary="Read and decrypt a secret")
async def kv_read(path: str, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    try: return ok(KVService(db, vault_state).read(path, p.user.email))
    except AppError as exc: denied_audit(db, request, p, "READ", "KV_SECRET", path, exc); raise


@router.delete("/kv/{path:path}", tags=["KV Engine"], summary="Delete a secret")
async def kv_delete(path: str, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    try: KVService(db, vault_state).delete(path, p.user.email); return ok({"deleted": True})
    except AppError as exc: denied_audit(db, request, p, "DELETE", "KV_SECRET", path, exc); raise


def transit_call(db, request, p, action, identifier, fn):
    try: return fn()
    except AppError as exc: denied_audit(db, request, p, action, "TRANSIT_KEY", identifier, exc); raise


@router.post("/transit/keys", tags=["Transit Keys"], summary="Create an AES named key")
async def key_create(body: CreateKeyRequest, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return ok(TransitService(db, vault_state).create_aes(p.user.email, body.key_name), 201)


@router.post("/transit/signing-keys", tags=["Transit Signing"], summary="Create an Ed25519 signing key")
async def signing_key_create(body: CreateSigningKeyRequest, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return ok(TransitService(db, vault_state).create_signing(p.user.email, body.key_name), 201)


@router.get("/transit/keys", tags=["Transit Keys"], summary="List key metadata")
async def key_list(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return ok(TransitService(db, vault_state).list(p.user.email))


@router.get("/transit/keys/{name}", tags=["Transit Keys"], summary="Get key metadata")
async def key_get(name: str, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return transit_call(db, request, p, "GET", name, lambda: ok(TransitService(db, vault_state).get(p.user.email, name)))


@router.delete("/transit/keys/{name}", tags=["Transit Keys"], summary="Revoke a key")
async def key_revoke(name: str, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    def call(): TransitService(db, vault_state).revoke(p.user.email, name); return ok({"revoked": True})
    return transit_call(db, request, p, "REVOKE", name, call)


@router.post("/transit/encrypt", tags=["Transit Encryption"], summary="Encrypt bytes with a named key")
async def transit_encrypt(body: EncryptRequest, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return transit_call(db, request, p, "ENCRYPT", body.key_name,
                        lambda: ok({"ciphertext": TransitService(db, vault_state).encrypt(p.user.email, body.key_name, body.plaintext_b64)}))


@router.post("/transit/decrypt", tags=["Transit Encryption"], summary="Decrypt a transit ciphertext")
async def transit_decrypt(body: DecryptRequest, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    name = body.ciphertext.split(":", 3)[2] if body.ciphertext.count(":") >= 3 else "malformed"
    return transit_call(db, request, p, "DECRYPT", name,
                        lambda: ok({"plaintext_b64": TransitService(db, vault_state).decrypt(p.user.email, body.ciphertext)}))


@router.post("/transit/sign", tags=["Transit Signing"], summary="Sign raw bytes or a SHA-256 digest")
async def transit_sign(body: SignRequest, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return transit_call(db, request, p, "SIGN", body.key_name,
                        lambda: ok(TransitService(db, vault_state).sign(p.user.email, body.key_name, body.message_b64, body.message_type)))


@router.post("/transit/verify", tags=["Transit Signing"], summary="Verify an Ed25519 signature")
async def transit_verify(body: VerifyRequest, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    return transit_call(db, request, p, "VERIFY", body.key_name,
                        lambda: ok(TransitService(db, vault_state).verify(p.user.email, body.key_name, body.message_b64, body.message_type, body.signature_b64)))
