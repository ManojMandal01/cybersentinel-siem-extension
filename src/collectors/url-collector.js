import { EVENT_TYPES } from '../shared/constants.js';
import { extractDomain, now } from '../shared/utils.js';

export function createUrlEvent(type, details) {
  const base = {
    event: type,
    timestamp: now(),
    url: details.url || '',
    domain: extractDomain(details.url || ''),
    tabId: details.tabId,
    frameId: details.frameId
  };

  switch (type) {
    case EVENT_TYPES.URL_VISIT:
      return { ...base, referrer: details.referrer || '', transitionType: details.transitionType };
    case EVENT_TYPES.URL_REDIRECT:
      return { ...base, fromUrl: details.fromUrl, redirectChain: details.redirectChain || [] };
    case EVENT_TYPES.TAB_OPENED:
      return { ...base, event: EVENT_TYPES.TAB_OPENED };
    case EVENT_TYPES.TAB_CLOSED:
      return { ...base, event: EVENT_TYPES.TAB_CLOSED };
    default:
      return base;
  }
}

export function initUrlCollector(onEvent) {
  const redirectChains = new Map();

  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;

    const event = createUrlEvent(EVENT_TYPES.URL_VISIT, {
      url: details.url,
      tabId: details.tabId,
      frameId: details.frameId,
      transitionType: details.transitionType
    });

    if (details.transitionQualifiers?.includes('server_redirect')) {
      const chain = redirectChains.get(details.tabId) || [];
      chain.push(details.url);
      redirectChains.set(details.tabId, chain);

      onEvent(createUrlEvent(EVENT_TYPES.URL_REDIRECT, {
        url: details.url,
        tabId: details.tabId,
        fromUrl: chain.length > 1 ? chain[chain.length - 2] : '',
        redirectChain: [...chain]
      }));
    }

    onEvent(event);
  });

  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    chrome.tabs.get(details.tabId).then((tab) => {
      if (tab?.url && tab.url !== details.url) {
        onEvent({
          event: EVENT_TYPES.URL_VISIT,
          timestamp: now(),
          url: details.url,
          domain: extractDomain(details.url),
          referrer: tab.url,
          tabId: details.tabId,
          transitionType: 'link'
        });
      }
    }).catch(() => {});
  });

  chrome.tabs.onCreated.addListener((tab) => {
    if (tab.pendingUrl || tab.url) {
      onEvent(createUrlEvent(EVENT_TYPES.TAB_OPENED, {
        url: tab.pendingUrl || tab.url,
        tabId: tab.id
      }));
    }
  });

  chrome.tabs.onRemoved.addListener((tabId) => {
    redirectChains.delete(tabId);
    onEvent({
      event: EVENT_TYPES.TAB_CLOSED,
      timestamp: now(),
      tabId
    });
  });
}
