// Wording checks in English and Bahasa Malaysia.

import { wordRegex } from './util.js';

export const PHRASE_GROUPS = [
  {
    id: 'urgency', sev: 'low', title: 'Pressure or urgency language',
    words: ['urgent', 'immediately', 'within 24 hours', 'within 48 hours', 'will be suspended', 'has been suspended', 'temporarily locked', 'will be closed', 'will be deactivated', 'final notice', 'final warning', 'action required', 'act now', 'expires today', 'last chance', 'segera', 'dalam masa 24 jam', 'akan disekat', 'telah disekat', 'akan digantung', 'tindakan segera', 'notis terakhir', 'amaran terakhir', 'akan ditamatkan'],
  },
  {
    id: 'credentials', sev: 'medium', title: 'Asks you to log in or confirm personal details',
    words: ['verify your account', 'verify your identity', 'confirm your password', 'confirm your account', 'confirm your identity', 'update your payment', 'update your account', 'update your details', 'unusual sign-in', 'unusual activity', 'reset your password', 're-enter your', 'log in to your account', 'login to your account', 'sign in to your account', 'validate your', 'sahkan akaun', 'sahkan identiti', 'kemas kini maklumat', 'kemaskini maklumat', 'log masuk', 'kata laluan', 'nombor tac', 'kod tac', 'nombor kad', 'nombor ic'],
  },
  {
    id: 'money', sev: 'low', title: 'Payment, invoice or refund lure',
    words: ['invoice', 'payment pending', 'wire transfer', 'bank details', 'change of bank', 'new bank account', 'remittance', 'refund', 'overdue', 'outstanding balance', 'tax refund', 'bayaran', 'invois', 'pemindahan wang', 'bayaran balik', 'tunggakan', 'saman tertunggak', 'akaun bank baharu'],
  },
  {
    id: 'prize', sev: 'low', title: 'Prize or reward lure',
    words: ['you have won', 'you won', 'claim your prize', 'claim your reward', 'lucky draw', 'free gift', 'selected winner', 'tahniah anda', 'cabutan bertuah', 'hadiah percuma', 'anda telah memenangi', 'tebus hadiah'],
  },
  {
    id: 'giftcard', sev: 'medium', title: 'Asks for gift cards (common in boss impersonation scams)',
    words: ['gift card', 'gift cards', 'google play card', 'itunes card', 'apple card', 'steam card', 'buy some cards', 'scratch the card', 'kad hadiah'],
  },
  {
    id: 'secrecy', sev: 'low', title: 'Asks to keep it secret or skip the normal process',
    words: ['keep this confidential', 'keep this between us', 'do not tell anyone', 'i am in a meeting', 'are you at your desk', 'reply only via email', 'urgent favour', 'urgent favor', 'jangan beritahu', 'rahsiakan'],
  },
  {
    id: 'delivery', sev: 'low', title: 'Parcel delivery problem lure',
    words: ['delivery failed', 'unable to deliver', 'parcel is on hold', 'customs fee', 'redelivery', 'shipment on hold', 'bungkusan anda', 'penghantaran gagal', 'caj kastam'],
  },
];

export function analyzeContent(text) {
  const hits = [];
  const t = String(text || '');
  for (const g of PHRASE_GROUPS) {
    const found = g.words.filter((w) => wordRegex(w).test(t));
    if (found.length) hits.push({ ...g, found });
  }
  return hits;
}
