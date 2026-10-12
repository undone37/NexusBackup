// The user manual is not served by the appliance: links open it in the project repository.
const BASE = 'https://github.com/undone37/NexusBackup/blob/main/manual/';

/** "15-troubleshooting-faq.md#check-disk-var" -> URL of that manual section. */
export const manualUrl = (anchor: string) => BASE + anchor.replace(/^\/+/, '');
