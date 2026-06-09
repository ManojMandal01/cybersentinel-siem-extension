import { SUSPICIOUS_EXTENSIONS } from '../shared/constants.js';
import { extractDomain, now } from '../shared/utils.js';

export function analyzeDownload(downloadItem) {
  const filename = downloadItem.filename || downloadItem.url || '';
  const ext = '.' + (filename.split('.').pop() || '').toLowerCase();
  const domain = extractDomain(downloadItem.url || '');

  return {
    event: 'download',
    timestamp: now(),
    file: filename.split(/[/\\]/).pop(),
    url: downloadItem.url,
    domain,
    extension: ext,
    mime: downloadItem.mime || '',
    fileSize: downloadItem.fileSize || 0,
    isSuspicious: SUSPICIOUS_EXTENSIONS.has(ext),
    danger: downloadItem.danger || 'safe',
    downloadId: downloadItem.id
  };
}

export function initDownloadMonitor(onEvent) {
  chrome.downloads.onCreated.addListener((downloadItem) => {
    onEvent(analyzeDownload(downloadItem));
  });

  chrome.downloads.onChanged.addListener((delta) => {
    if (delta.state?.current === 'complete') {
      chrome.downloads.search({ id: delta.id }, (items) => {
        if (items[0]) onEvent({ ...analyzeDownload(items[0]), state: 'complete' });
      });
    }
  });
}
