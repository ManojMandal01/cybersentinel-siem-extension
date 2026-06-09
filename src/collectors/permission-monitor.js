import { now } from '../shared/utils.js';

export function createPermissionEvent(type, details) {
  return {
    event: 'permission_access',
    timestamp: now(),
    permissionType: type,
    domain: details.domain,
    url: details.url,
    tabId: details.tabId,
    camera_access: type === 'camera',
    microphone_access: type === 'microphone',
    clipboard_access: type === 'clipboard',
    notification_access: type === 'notification'
  };
}

export function processPermissionMessage(message) {
  return createPermissionEvent(message.permissionType, {
    domain: message.domain,
    url: message.url,
    tabId: message.tabId
  });
}
