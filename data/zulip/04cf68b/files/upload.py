import base64
import binascii
import os
from datetime import timedelta
from mimetypes import guess_type
from typing import Optional, Union
from urllib.parse import quote, urlparse

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.core.files.uploadedfile import UploadedFile
from django.core.signing import BadSignature, TimestampSigner
from django.http import (
    FileResponse,
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseForbidden,
    HttpResponseNotFound,
)
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.cache import patch_cache_control
from django.utils.translation import gettext as _

from zerver.context_processors import get_valid_realm_from_request
from zerver.lib.exceptions import JsonableError
from zerver.lib.response import json_success
from zerver.lib.upload import (
    check_upload_within_quota,
    get_public_upload_root_url,
    upload_message_image_from_request,
)
from zerver.lib.upload.base import INLINE_MIME_TYPES
from zerver.lib.upload.local import assert_is_local_storage_path
from zerver.lib.upload.s3 import get_signed_upload_url
from zerver.models import UserProfile, validate_attachment_request


def patch_disposition_header(response: HttpResponse, url: str, is_attachment: bool) -> None:
    """
    This replicates django.utils.http.content_disposition_header's
    algorithm, which is introduced in Django 4.2.

    """
    # TODO: Replace this with django.utils.http.content_disposition_header when we upgrade in Django 4.2
    disposition = "attachment" if is_attachment else "inline"

    # Trim to only the filename part of the URL
    filename = os.path.basename(urlparse(url).path)

    # Content-Disposition is defined in RFC 6266:
    # https://datatracker.ietf.org/doc/html/rfc6266
    #
    # For the 'filename' attribute of it, see RFC 8187:
    # https://datatracker.ietf.org/doc/html/rfc8187
    try:
        # If the filename is pure-ASCII (determined by trying to
        # encode it as such), then we escape slashes and quotes, and
        # provide a filename="..."
        filename.encode("ascii")
        file_expr = 'filename="{}"'.format(filename.replace("\\", "\\\\").replace('"', r"\""))
    except UnicodeEncodeError:
        # If it contains non-ASCII characters, we URI-escape it and
        # provide a filename*=encoding'language'value
        file_expr = "filename*=utf-8''{}".format(quote(filename))

    response.headers["Content-Disposition"] = f"{disposition}; {file_expr}"


def internal_nginx_redirect(internal_path: str) -> HttpResponse:
    # The following headers from this initial response are
    # _preserved_, if present, and sent unmodified to the client;
    # all other headers are overridden by the redirected URL:
    #  - Content-Type
    #  - Content-Disposition
    #  - Accept-Ranges
    #  - Set-Cookie
    #  - Cache-Control
    #  - Expires
    # As such, we unset the Content-type header to allow nginx to set
    # it from the static file; the caller can set Content-Disposition
    # and Cache-Control on this response as they desire, and the
    # client will see those values.
    response = HttpResponse()
    response["X-Accel-Redirect"] = internal_path
    del response["Content-Type"]
    return response


def serve_s3(
    request: HttpRequest, url_path: str, url_only: bool, download: bool = False
) -> HttpResponse:
    url = get_signed_upload_url(url_path, download=download)
    if url_only:
        return json_success(request, data=dict(url=url))

    return redirect(url)


def serve_local(
    request: HttpRequest, path_id: str, url_only: bool, download: bool = False
) -> HttpResponseBase:
    assert settings.LOCAL_FILES_DIR is not None
    local_path = os.path.join(settings.LOCAL_FILES_DIR, path_id)
    assert_is_local_storage_path("files", local_path)
    if not os.path.isfile(local_path):
        return HttpResponseNotFound("<p>File not found</p>")

    if url_only:
        url = generate_unauthed_file_access_url(path_id)
        return json_success(request, data=dict(url=url))

    mimetype, encoding = guess_type(local_path)
    attachment = download or mimetype not in INLINE_MIME_TYPES

    if settings.DEVELOPMENT:
        # In development, we do not have the nginx server to offload
        # the response to; serve it directly ourselves.
        # FileResponse handles setting Content-Disposition, etc.
        response: HttpResponseBase = FileResponse(open(local_path, "rb"), as_attachment=attachment)
        patch_cache_control(response, private=True, immutable=True)
        return response

    response = internal_nginx_redirect(quote(f"/internal/uploads/{path_id}"))
    patch_disposition_header(response, local_path, attachment)
    patch_cache_control(response, private=True, immutable=True)
    return response


def serve_file_download_backend(
    request: HttpRequest, user_profile: UserProfile, realm_id_str: str, filename: str
) -> HttpResponseBase:
    return serve_file(request, user_profile, realm_id_str, filename, url_only=False, download=True)


def serve_file_backend(
    request: HttpRequest,
    maybe_user_profile: Union[UserProfile, AnonymousUser],
    realm_id_str: str,
    filename: str,
) -> HttpResponseBase:
    return serve_file(request, maybe_user_profile, realm_id_str, filename, url_only=False)


def serve_file_url_backend(
    request: HttpRequest, user_profile: UserProfile, realm_id_str: str, filename: str
) -> HttpResponseBase:
    """
    We should return a signed, short-lived URL
    that the client can use for native mobile download, rather than serving a redirect.
    """

    return serve_file(request, user_profile, realm_id_str, filename, url_only=True)


def serve_file(
    request: HttpRequest,
    maybe_user_profile: Union[UserProfile, AnonymousUser],
    realm_id_str: str,
    filename: str,
    url_only: bool = False,
    download: bool = False,
) -> HttpResponseBase:
    path_id = f"{realm_id_str}/{filename}"
    realm = get_valid_realm_from_request(request)
    is_authorized = validate_attachment_request(maybe_user_profile, path_id, realm)

    if is_authorized is None:
        return HttpResponseNotFound(_("<p>File not found.</p>"))
    if not is_authorized:
        return HttpResponseForbidden(_("<p>You are not authorized to view this file.</p>"))
    if settings.LOCAL_UPLOADS_DIR is not None:
        return serve_local(request, path_id, url_only, download=download)

    return serve_s3(request, path_id, url_only, download=download)


LOCAL_FILE_ACCESS_TOKEN_SALT = "local_file_"


def generate_unauthed_file_access_url(path_id: str) -> str:
    signed_data = TimestampSigner(salt=LOCAL_FILE_ACCESS_TOKEN_SALT).sign(path_id)
    token = base64.b16encode(signed_data.encode()).decode()

    filename = path_id.split("/")[-1]
    return reverse("local_file_unauthed", args=[token, filename])


def get_local_file_path_id_from_token(token: str) -> Optional[str]:
    signer = TimestampSigner(salt=LOCAL_FILE_ACCESS_TOKEN_SALT)
    try:
        signed_data = base64.b16decode(token).decode()
        path_id = signer.unsign(signed_data, max_age=timedelta(seconds=60))
    except (BadSignature, binascii.Error):
        return None

    return path_id


def serve_local_file_unauthed(request: HttpRequest, token: str, filename: str) -> HttpResponseBase:
    path_id = get_local_file_path_id_from_token(token)
    if path_id is None:
        raise JsonableError(_("Invalid token"))
    if path_id.split("/")[-1] != filename:
        raise JsonableError(_("Invalid filename"))

    return serve_local(request, path_id, url_only=False)


def serve_local_avatar_unauthed(request: HttpRequest, path: str) -> HttpResponseBase:
    """Serves avatar images off disk, via nginx (or directly in dev), with no auth.

    This is done unauthed because these need to be accessed from HTML
    emails, where the client does not have any auth.  We rely on the
    URL being generated using the AVATAR_SALT secret.

    """
    if settings.LOCAL_AVATARS_DIR is None:
        # We do not expect clients to hit this URL when using the S3
        # backend; however, there is no reason to not serve the
        # redirect to S3 where the content lives.
        return redirect(
            get_public_upload_root_url() + path + "?" + request.GET.urlencode(), permanent=True
        )

    local_path = os.path.join(settings.LOCAL_AVATARS_DIR, path)
    assert_is_local_storage_path("avatars", local_path)
    if not os.path.isfile(local_path):
        return HttpResponseNotFound("<p>File not found</p>")

    if settings.DEVELOPMENT:
        response: HttpResponseBase = FileResponse(open(local_path, "rb"))
    else:
        response = internal_nginx_redirect(quote(f"/internal/user_avatars/{path}"))

    # We do _not_ mark the contents as immutable for caching purposes,
    # since the path for avatar images is hashed only by their user-id
    # and a salt, and as such are reused when a user's avatar is
    # updated.
    return response


def upload_file_backend(request: HttpRequest, user_profile: UserProfile) -> HttpResponse:
    if len(request.FILES) == 0:
        raise JsonableError(_("You must specify a file to upload"))
    if len(request.FILES) != 1:
        raise JsonableError(_("You may only upload one file at a time"))

    user_file = list(request.FILES.values())[0]
    assert isinstance(user_file, UploadedFile)
    file_size = user_file.size
    assert file_size is not None
    if settings.MAX_FILE_UPLOAD_SIZE * 1024 * 1024 < file_size:
        raise JsonableError(
            _("Uploaded file is larger than the allowed limit of {} MiB").format(
                settings.MAX_FILE_UPLOAD_SIZE,
            )
        )
    check_upload_within_quota(user_profile.realm, file_size)

    uri = upload_message_image_from_request(user_file, user_profile, file_size)
    return json_success(request, data={"uri": uri})
