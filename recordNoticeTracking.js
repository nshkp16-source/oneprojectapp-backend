const FIRST_OPEN_NOTICE_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;

export function getNewRecordNoticeIds(notices, lastOpenedAt, isOwnNotice, now = Date.now()) {
  const openedAt = lastOpenedAt ? new Date(lastOpenedAt).getTime() : now - FIRST_OPEN_NOTICE_WINDOW_MS;
  if (!Number.isFinite(openedAt)) return [];

  return (Array.isArray(notices) ? notices : [])
    .filter(notice => {
      if (isOwnNotice(notice)) return false;
      const issuedAt = new Date(notice.issued_date || notice.signed_at || '').getTime();
      return Number.isFinite(issuedAt) && issuedAt > openedAt;
    })
    .map(notice => notice.id);
}
