/* CTI Casefile — Scenario definition
 * Pure data. Loaded as a classic script so the app also works from file://
 * (fetch() of JSON would be blocked by CORS on a local disk).
 *
 * Source of truth for content: ../new.scenario (beginner-password-reset-abuse-001)
 *
 * Note on answer order: the engine re-orders every question from the case seed
 * (see shuffleCase in app.js), so the order below is only the authoring order.
 * It is deliberately varied anyway — no single-answer question puts the correct
 * option first, and no multi-select question puts the correct options in the
 * leading slots — so the source is safe to read even without the shuffle.
 */
(function () {
  window.CTI_SCENARIOS = window.CTI_SCENARIOS || [];

  window.CTI_SCENARIOS.push({
    id: 'beginner-password-reset-abuse-001',
    title: 'Five New Passwords',
    difficulty: 'Beginner',
    seed: 113,
    caseRef: 'CASE 010',
    host: 'sec-win-05',
    host_ip: '10.0.4.12',
    log_sources: ['auth'],

    mission: {
      brief: 'Investigate workstation sec-win-05.',
      objective: 'Establish who reset five passwords on this host, and what they were used for afterwards.',
      client: 'Internal Security Operations — Tier 1 Escalation Desk'
    },

    narrative:
      'An attacker with a foothold on a workstation reset the passwords of five different user accounts in a ' +
      'three-minute window, then authenticated as two of those users. Mass password resets followed by ' +
      'immediate logins is a strong sign that someone other than the helpdesk is taking over accounts.',

    /* ---------------------------------------------------------------
     * Strings the engine reads from the scenario, so no fact about this
     * case is written into app.js. Every value here comes from new.scenario;
     * the evidence, stream and questions that follow are built on it.
     * --------------------------------------------------------------- */
    engine: {
      /* stage 2 — the record stream banner */
      stream: {
        window: '08:00–08:45',
        files: ['secwin5-events.evtx']
      },

      /* stage 5 / 6 — section headings and the progress checklist labels */
      sections: {
        behaviour: 'name the behaviour',
        second: 'read the reset records',
        trail: 'assemble the sequence',
        attack: 'map it to attack',
        attackAlso: 'supporting techniques',
        iocs: 'keep the intelligence'
      },

      /* stage 1 — the three questions the analyst carries into the data */
      carryQuestions: [
        'Who is allowed to reset another user\u2019s password on this estate, and is that person logged on?',
        'How many accounts were touched, in what window \u2014 and what does that number say about intent?',
        'Which of the reset accounts were then used, and where did those logons come from?'
      ],

      /* stage 3 — what the cadence of the sequence means */
      cadenceNote:
        'The order is the finding: five resets in two minutes forty seconds from a session that came from ' +
        'outside, then a logon as asmith from that same address three minutes later, then a logon as jdoe from ' +
        'it again, then a command shell inside the asmith session. The resets are preparation; the logons ' +
        'are the answer to whether it worked.',

      /* ledger wording, so the analyst journal reads in the case's own terms */
      awards: {
        evidence:
          'Reviewed the full evidence set: three alerts plus delegation and account reference data',
        timeline:
          'Identified the pattern: five passwords reset in under three minutes, then two of those accounts used',
        triageContext:
          'Kept the compromised logon as context rather than evidence — it names the session, not the resets',
        board:
          'Correlated the full chain: kpatel session → five resets → asmith and jdoe log on → shell inside ' +
          'asmith\u2019s session',
        attack: 'Mapped the outcome to ATT&CK T1110.001 Password Guessing: Password Reset',
        attackAlso:
          'Identified the supporting technique: T1078 Valid Accounts — and noted which three accounts the ' +
          'attacker never used',
        host: 'Scoped the incident to host sec-win-05'
      },

      /* stage 5 — the collapsed trail card, and its journal entry */
      trailRows: [
        { k: 'Subject', v: 'kpatel', flag: '— Marketing Coordinator, no reset rights' },
        { k: 'Reset', v: '5 accounts', flag: '— jdoe, asmith, mchen, rneuman, svega' },
        { k: 'Used', v: 'asmith, jdoe', flag: '— mchen, rneuman and svega were never touched again' },
        { k: 'Trail', v: 'kpatel 08:01:44 → 5 × 4724 08:04:37–08:07:14 → asmith 4624 08:10:26 → jdoe 4624 08:12:03 → cmd.exe 08:14:19' }
      ],
      trailLabel: 'REVEAL THE FULL RESET TRAIL',
      journalDecode:
        'Assembled the reset trail — session as kpatel at 08:01:44, five resets between 08:04:37 and ' +
        '08:07:14, logon as asmith at 08:10:26, jdoe at 08:12:03, cmd.exe at 08:14:19',

      /* stage 6 — the live assessment preview */
      reportPreview: {
        rows: [
          { label: 'Host', value: 'sec-win-05 (10.0.4.12)', code: true },
          { label: 'Reset by', value: 'kpatel — not in Helpdesk or Domain Admins', code: true },
          { label: 'Accounts reset', value: '5 — jdoe, asmith, mchen, rneuman, svega', code: true },
          { label: 'Accounts used', value: '2 — asmith (08:10:26) and jdoe (08:12:03), both from 203.0.113.45', code: true },
          { label: 'Never used', value: '3 — mchen, rneuman, svega', code: false },
          { label: 'TTP', value: 'Password Guessing: Password Reset T1110.001 — credential access', code: false }
        ],
        note:
          'Assemble your justification in the fields above. The assessment is only defensible if the reasoning ' +
          'is visible.'
      }
    },

    /* ---------------------------------------------------------------
     * STAGE 2 — TRIAGE
     * The student tags each event as signal / context / noise.
     * tags: 'signal' | 'context' | 'noise'
     * --------------------------------------------------------------- */
    events: [
      {
        id: 'ev-4624-kpatel',
        ts: '08:01:44',
        code: 4624,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'kpatel',
        text: 'Successful logon. Account "kpatel". Logon type 2 (interactive). Source 203.0.113.45.',
        tags: 'context',
        why:
          'The session every reset will be attributed to, and nothing more in itself. It matters because of where ' +
          'it came from: 203.0.113.45 is outside the estate, so the account whose name appears on the resets is ' +
          'a label rather than an actor.'
      },
      {
        id: 'ev-4724-jdoe',
        ts: '08:04:37',
        code: 4724,
        kind: 'event',
        host: 'sec-win-05',
        text: 'Password reset. Target account: jdoe. Reset by: kpatel. Target server: CORP. Method: ADSelfReset.',
        tags: 'signal',
        why:
          'First of five. Note the subject and the method: this was done as the account holder, not by the ' +
          'helpdesk process that owns password resets on this estate. One reset can be a user helping a ' +
          'colleague; the pattern is what makes this a finding.'
      },
      {
        id: 'ev-4724-asmith',
        ts: '08:05:11',
        code: 4724,
        kind: 'event',
        host: 'sec-win-05',
        text: 'Password reset. Target account: asmith. Reset by: kpatel. Target server: CORP. Method: ADSelfReset.',
        tags: 'signal',
        why:
          '34 seconds later, a second account, same subject, same method. A self-service reset can only ever ' +
          'reset the account\u2019s own password, so five of these from one session is not five users helping ' +
          'each other \u2014 it is one identity being used five times.'
      },
      {
        id: 'ev-4724-mchen',
        ts: '08:05:48',
        code: 4724,
        kind: 'event',
        host: 'sec-win-05',
        text: 'Password reset. Target account: mchen. Reset by: kpatel. Target server: CORP. Method: ADSelfReset.',
        tags: 'signal',
        why:
          'Third inside 71 seconds. Nobody resets three colleagues\u2019 passwords in a minute; the rate is the ' +
          'finding, and each record adds to a single story rather than being a separate event.'
      },
      {
        id: 'ev-4724-rneuman',
        ts: '08:06:29',
        code: 4724,
        kind: 'event',
        host: 'sec-win-05',
        text: 'Password reset. Target account: rneuman. Reset by: kpatel. Target server: CORP. Method: ADSelfReset.',
        tags: 'signal',
        why:
          'Fourth. By now the account is being used as a way to mint credentials for other people \u2014 which is ' +
          'the one move in this case that has no legitimate reading at all.'
      },
      {
        id: 'ev-4724-svega',
        ts: '08:07:14',
        code: 4724,
        kind: 'event',
        host: 'sec-win-05',
        text: 'Password reset. Target account: svega. Reset by: kpatel. Target server: CORP. Method: ADSelfReset.',
        tags: 'signal',
        why:
          'Fifth, and the last of the burst: five accounts in two minutes thirty-seven seconds, all attributed ' +
          'to one session. What the attacker did with them is in the three records that follow.'
      },
      {
        id: 'ev-4624-asmith',
        ts: '08:10:26',
        code: 4624,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'asmith',
        text: 'Successful logon. Account "asmith". Logon type 2 (interactive). Source 203.0.113.45.',
        tags: 'signal',
        why:
          'Three minutes after the burst, the first reset account authenticates \u2014 from the same external ' +
          'address that opened the kpatel session. That closes the loop the resets set up: the password was ' +
          'changed so it could be used, and it was used from where the session came from.'
      },
      {
        id: 'ev-4624-jdoe',
        ts: '08:12:03',
        code: 4624,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'jdoe',
        text: 'Successful logon. Account "jdoe". Logon type 2 (interactive). Source 203.0.113.45.',
        tags: 'signal',
        why:
          'The second of the five, 97 seconds after the first, from the same address. Two of five accounts were ' +
          'used and three were not, which is the scoping question: whoever did this had time and stopped ' +
          'after two.'
      },
      {
        id: 'ev-4688-cmd',
        ts: '08:14:19',
        code: 4688,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'asmith',
        text: 'Process created by asmith: cmd.exe (Command Prompt). Parent: winlogon.exe.',
        tags: 'signal',
        why:
          'A command shell inside the asmith session, parented by winlogon \u2014 an interactive logon now exists ' +
          'under an account whose password was changed four minutes earlier by someone else. This is what the ' +
          'credential was for.'
      },

      /* ---------- noise: baseline user activity ---------- */
      { id: 'ev-n01', ts: '08:00:38', code: 4624, kind: 'event', host: 'FIN-WS-14', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n02', ts: '08:02:09', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'mchen', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n03', ts: '08:02:54', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'tlopez', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n04', ts: '08:03:46', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'jhgarcia', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n05', ts: '08:05:09', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'mchen', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n06', ts: '08:05:35', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n07', ts: '08:06:46', code: 4634, kind: 'event', host: 'HR-LT-03', actor: 'tlopez', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n08', ts: '08:07:51', code: 4672, kind: 'event', host: 'OPS-WS-09', actor: 'jhgarcia', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n09', ts: '08:08:14', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n10', ts: '08:09:27', code: 4634, kind: 'event', host: 'OPS-WS-09', actor: 'jhgarcia', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n11', ts: '08:10:42', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'rneuman', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n12', ts: '08:11:49', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n13', ts: '08:12:56', code: 4634, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n14', ts: '08:14:25', code: 4624, kind: 'event', host: 'HR-LT-03', actor: 'tlopez', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n15', ts: '08:16:37', code: 4634, kind: 'event', host: 'ENG-WS-02', actor: 'svega', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n16', ts: '08:17:11', code: 4672, kind: 'event', host: 'FIN-WS-14', actor: 'mchen', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n17', ts: '08:19:28', code: 4624, kind: 'event', host: 'SALES-LT-11', actor: 'jhgarcia', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n18', ts: '08:21:45', code: 4634, kind: 'event', host: 'SALES-LT-11', actor: 'rneuman', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n19', ts: '08:24:08', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'tlopez', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n20', ts: '08:26:21', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'svega', text: 'Special privileges assigned to new logon.', tags: 'noise' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 1 — EVIDENCE INBOX
     * --------------------------------------------------------------- */
    evidence: [
      {
        id: 'al-4724-burst',
        ref: 'ALERT-01',
        severity: 'high',
        title: 'Multiple password resets from single user',
        blurb: "Five password reset events (Event 4724) were recorded on sec-win-05, all initiated by user 'kpatel', targeting accounts jdoe, asmith, mchen, rneuman, and svega.",
        detail:
          'Security Event 4724 \u2014 "An attempt was made to reset an account\u2019s password" \u2014 five times ' +
          'between 08:04:37 and 08:07:14, every one with SubjectUserName kpatel and Method ADSelfReset. ' +
          'ADSelfReset is the self-service path, and a self-service reset can only change the subject\u2019s own ' +
          'password \u2014 five of them from one session is therefore one identity doing something five times, ' +
          'not five users helping each other.',
        hint: 'Ask: who can reset another user\u2019s password here, and does the method on these records permit it?'
      },
      {
        id: 'al-unauthorised',
        ref: 'ALERT-02',
        severity: 'high',
        title: 'Password resets outside helpdesk procedure',
        blurb: "User 'kpatel' is not a member of the Helpdesk or Domain Admins group and is not authorised to reset passwords for other users.",
        detail:
          'Group membership for kpatel: Domain Users and Marketing-Read. Delegated password-reset rights on ' +
          'this estate are granted to the Helpdesk group only, and every helpdesk reset is performed by the ' +
          'service account HD-Reset through a ticket. In 90 days this account has reset no password, for ' +
          'itself or anyone else. There is no ticket matching any of these five events \u2014 the helpdesk queue ' +
          'was empty between 07:00 and 09:00.',
        hint: 'Ask: what should have happened if a reset was genuinely needed, and did it happen at all?'
      },
      {
        id: 'al-new-logons',
        ref: 'ALERT-03',
        severity: 'high',
        title: 'New logons by accounts whose passwords were just reset',
        blurb: 'Two of the reset accounts (asmith, jdoe) authenticated to sec-win-05 within minutes of their password change, indicating the attacker used the new credentials.',
        detail:
          'Event 4624 for asmith at 08:10:26 and for jdoe at 08:12:03, both logon type 2, both from ' +
          '203.0.113.45 \u2014 the address that opened the kpatel session at 08:01:44. Neither account has ' +
          'logged on from that address in 90 days. This is the record that converts an odd activity into a ' +
          'credential takeover: the resets were not for the accounts\u2019 own benefit.',
        hint: 'Ask: which of the five were used, and does the source of those logons match anything earlier?'
      },
      {
        id: 'ev-user',
        ref: 'EVID-04',
        severity: 'info',
        title: 'Account information — kpatel',
        blurb: 'Directory record for the account the resets were attributed to.',
        detail:
          'kpatel \u2014 K. Patel, Marketing Coordinator, 34 months in post. Group membership: Domain Users and ' +
          'Marketing-Read. No Helpdesk membership, no password-reset delegation, no administrative rights. ' +
          'Password age 191 days, unchanged since onboarding. Interactive logon history for 90 days: ' +
          '10.0.4.x and VPN concentrator addresses only \u2014 never 203.0.113.45.',
        hint: 'Ask: is there any delegated right here, and has this address ever belonged to this user?'
      },
      {
        id: 'ev-baseline',
        ref: 'EVID-05',
        severity: 'info',
        title: 'Baseline activity — resets and logons this hour',
        blurb: 'Reference records for the estate during the same window.',
        detail:
          'Estate-wide in this hour: 6 password reset events, all performed by HD-Reset against ticket ' +
          'HD-4471 and HD-4478 \u2014 none of them these five. Self-service resets in the last 30 days: 41, all ' +
          'single events, all resetting the account\u2019s own password, none within four minutes of another. ' +
          'Five baseline users generated 20 logon, logoff and privilege events across FIN-WS-14, HR-LT-03, ' +
          'ENG-WS-02, OPS-WS-09, FIN-LT-11 and SALES-LT-11. No account in the estate has ever authenticated ' +
          'interactively from 203.0.113.45 before today.',
        hint: 'Ask: what does a legitimate reset look like here, and does any of it look like this?'
      }
    ],

    alerts: [
      { name: 'Multiple password resets from single user', severity: 'high' },
      { name: 'Password resets outside helpdesk procedure', severity: 'high' },
      { name: 'New logons by accounts whose passwords were just reset', severity: 'high' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 3 — TIMELINE
     * --------------------------------------------------------------- */
    timeline: [
      { t: 'T+0', ts: '08:01:44', label: 'Logon', detail: "1 successful logon for 'kpatel' on sec-win-05 from 203.0.113.45 (compromised session)", net: null },
      { t: 'T+3', ts: '08:04:37', label: 'Resets', detail: 'password_reset (4724) ×5 on sec-win-05 for jdoe, asmith, mchen, rneuman and svega, running to 08:07:14', net: null },
      { t: 'T+6', ts: '08:10:26', label: 'Logon', detail: "successful_logon (4624) for 'asmith' on sec-win-05 from 203.0.113.45", net: null },
      { t: 'T+8', ts: '08:12:03', label: 'Logon', detail: "successful_logon (4624) for 'jdoe' on sec-win-05 from 203.0.113.45", net: null },
      { t: 'T+10', ts: '08:14:19', label: 'Process', detail: "process_created (4688): cmd.exe spawned by 'asmith' on sec-win-05", net: null }
    ],

    timelineQuestion: {
      id: 'q-timeline',
      prompt: 'What pattern do you see in this sequence?',
      options: [
        { id: 'a', label: 'A helpdesk engineer clearing five forgotten passwords together during a quiet hour' },
        { id: 'b', label: 'Five colleagues each resetting their own password shortly after logging in' },
        { id: 'c', label: 'A session that changed five accounts\u2019 passwords in under three minutes, then signed in as two of them' },
        { id: 'd', label: 'A password-expiry policy firing across the estate and forcing five users to reset at once' }
      ],
      correct: ['c'],
      xp: 10,
      explain:
        'The alternatives need either the method or the subject to be different from what the records show. ' +
        'Helpdesk resets are performed by the HD-Reset service against a ticket, not by a user session; self-' +
        'service resets can only change the account\u2019s own password, so five from one session is not five ' +
        'colleagues; and an expiry policy produces prompts, not 4724 events with a SubjectUserName. What the ' +
        'sequence shows is one session minting credentials and then spending them.'
    },

    /* ---------------------------------------------------------------
     * STAGE 4 — CORRELATION BOARD
     * --------------------------------------------------------------- */
    boardNodes: [
      { id: 'n-session', label: 'kpatel session', sub: 'from 203.0.113.45', x: 8, y: 8 },
      { id: 'n-resets', label: '5 × Event 4724', sub: 'in 2m37s', x: 8, y: 62 },
      { id: 'n-fiverecs', label: '5 accounts', sub: 'jdoe, asmith, mchen, rneuman, svega', x: 40, y: 36 },
      { id: 'n-asmith', label: 'asmith', sub: 'logged on 08:10:26', x: 40, y: 82 },
      { id: 'n-jdoe', label: 'jdoe', sub: 'logged on 08:12:03', x: 72, y: 8 },
      { id: 'n-shell', label: 'cmd.exe', sub: 'inside asmith\u2019s session', x: 72, y: 62 }
    ],
    boardLinks: [
      { from: 'n-session', to: 'n-resets', label: 'authorised by', correct: false },
      { from: 'n-resets', to: 'n-fiverecs', label: 'targets', correct: true },
      { from: 'n-fiverecs', to: 'n-asmith', label: 'includes', correct: true },
      { from: 'n-fiverecs', to: 'n-jdoe', label: 'includes', correct: true },
      { from: 'n-asmith', to: 'n-shell', label: 'spawns', correct: true },
      { from: 'n-session', to: 'n-resets', label: 'resets', correct: true },
      { from: 'n-jdoe', to: 'n-shell', label: 'spawns', correct: false }
    ],
    boardXp: 10,

    /* ---------------------------------------------------------------
     * STAGE 5 — ANALYSIS: behaviour, ATT&CK, IoCs
     * --------------------------------------------------------------- */
    behaviourQuestions: [
      {
        id: 'q-persist',
        prompt: 'How would you classify resetting other users\u2019 passwords and then signing in as them?',
        options: [
          { id: 'a', label: 'Impact \u2014 other people\u2019s accounts have been taken over and data is at risk' },
          { id: 'b', label: 'Credential access \u2014 the attacker obtained usable credentials for accounts that were not theirs' },
          { id: 'c', label: 'Initial Access \u2014 this is how the attacker entered the estate' },
          { id: 'd', label: 'Persistence \u2014 the changed passwords will still be in place next month' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'The output of this activity is credentials: five sets that now belong to somebody else and can be used ' +
          'at leisure. That is credential access, and the two logons that follow are the attacker spending what ' +
          'the resets produced. It is not initial access \u2014 the kpatel session at 08:01:44 preceded all of it ' +
          '\u2014 and while the changes do persist on disk, persistence describes how access is kept, not how ' +
          'credentials are won.'
      },
      {
        id: 'q-ps',
        prompt: 'Why does it matter that only two of the five reset accounts were subsequently used?',
        options: [
          { id: 'a', label: 'It does not \u2014 any use at all would make the case' },
          { id: 'b', label: 'It means the other three were abandoned, and identifying which accounts were used is what scopes the response' },
          { id: 'c', label: 'It proves the reset only worked for accounts in the same department' },
          { id: 'd', label: 'It suggests the five reset events were actually a single event logged five times' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'Five resets and two uses is a sequence with stages: mint, then spend, then stop. It bounds the ' +
          'response \u2014 two accounts were demonstrably compromised, and three were changed but never used from ' +
          'this address, which is a different and much less alarming conversation to have with those three ' +
          'people. It also dates the operation: the attacker had a session window and left before using all ' +
          'of them.'
      }
    ],

    decodedCommand: {
      encoded: 'kpatel 08:01:44 \u2192 5 × 4724 08:04:37\u201308:07:14 \u2192 4624 asmith 08:10:26 \u2192 4624 jdoe 08:12:03 \u2192 4688 cmd.exe 08:14:19',
      decoded: 'unprivileged external session (4624) \u2192 five password resets (4724) \u2192 two of those accounts authenticate (4624) \u2192 command shell inside the first (4688)',
      note:
        'The nine records read as one operation with three stages: take a session, mint credentials for five ' +
        'accounts, then spend two of them. The five resets are the middle of the story, not the whole of it \u2014 ' +
        'a report that stops at the last 4724 has described an unusual administrative act rather than an ' +
        'intrusion.'
    },

    attack: {
      /* the engine renders primary.prompt and alsoPresent.prompt as the question text */
      primary: {
        prompt: 'Which technique best explains how the attacker obtained those credentials?',
        options: [
          { id: 'a', label: 'Credentials from Password Stores', meta: 'T1555 \u00b7 Credential Access' },
          { id: 'b', label: 'Brute Force: Password Spraying', meta: 'T1110.003 \u00b7 Credential Access' },
          { id: 'c', label: 'Password Guessing: Password Reset', meta: 'T1110.001 \u00b7 Credential Access' },
          { id: 'd', label: 'Modify Authentication Process', meta: 'T1556 \u00b7 Credential Access / Persistence' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'No password was guessed, sprayed or read out of a store: the attacker reset them, which is Password ' +
          'Guessing: Password Reset, T1110.001 \u2014 the sub-technique that covers triggering a reset flow to make ' +
          'a chosen credential valid. The spray sub-technique (T1110.003) is the one people reach for first and ' +
          'it describes nothing here: every reset succeeded, so nothing was guessed at all.'
      },
      alsoPresent: {
        prompt: 'One further technique is genuinely present. Select it.',
        options: [
          { id: 'a', label: 'Valid Accounts', meta: 'T1078 \u00b7 Defense Evasion / Persistence / Privilege Escalation' },
          { id: 'b', label: 'Exploitation for Privilege Escalation', meta: 'T1068 \u00b7 Privilege Escalation' },
          { id: 'c', label: 'Scheduled Task/Job', meta: 'T1053.005 \u00b7 Execution / Persistence' },
          { id: 'd', label: 'OS Credential Dumping: SAM', meta: 'T1003.002 \u00b7 Credential Access' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'The credentials were then used \u2014 asmith and jdoe authenticated interactively, and a command shell ' +
          '\u2014 which is Valid Accounts, T1078, applied to credentials the attacker had just made valid. It is ' +
          'the second half of the operation and it is what turns a policy abuse into an account takeover. ' +
          'Nothing was exploited (B), no task was created (C), and nothing was read out of the registry (D).'
      }
    },

    iocs: {
      prompt: 'Which of these would you preserve as indicators or investigative pivots?',
      options: [
        { id: 'i1', label: '203.0.113.45', role: 'indicator' },
        { id: 'i2', label: '4724 with a subject holding no password-reset delegation', role: 'indicator' },
        { id: 'i3', label: 'sec-win-05', role: 'context' },
        { id: 'i4', label: 'kpatel', role: 'context' },
        { id: 'i5', label: 'Event 4724', role: 'context' },
        { id: 'i6', label: 'five resets attributed to one session in under three minutes', role: 'behaviour' },
        { id: 'i7', label: 'an account authenticating minutes after its password was changed by another identity', role: 'behaviour' },
        { id: 'i8', label: 'a self-service reset method used against accounts other than the subject', role: 'behaviour' }
      ],
      correct: ['indicator', 'behaviour', 'context'],
      xp: 10,
      explain:
        'Two of these eight are things you act on today: the external address 203.0.113.45, and the detection ' +
        'rule \u2014 any 4724 whose subject holds no reset delegation, which is a check you can run across every ' +
        'reset the domain performs. The behaviours are what to engineer: a burst attributed to one session, an ' +
        'account authenticating immediately after somebody else changed its password, and a self-service method ' +
        'used against accounts other than the subject \u2014 which should be impossible and is worth alerting on ' +
        'regardless of what else this case concludes. sec-win-05, kpatel and Event 4724 itself are context.'
    },

    /* ---------------------------------------------------------------
     * STAGE 6 — REPORT
     * --------------------------------------------------------------- */
    report: {
      host: {
        prompt: 'Which host is affected?',
        options: [
          { id: 'a', label: 'FIN-LT-11' },
          { id: 'b', label: 'HR-LT-03' },
          { id: 'c', label: '10.0.4.20' },
          { id: 'd', label: 'sec-win-05' }
        ],
        correct: ['d'],
        xp: 10,
        explain:
          'All nine relevant records originate on sec-win-05, including both of the logons that followed the ' +
          'burst. 10.0.4.20 appears elsewhere in the estate and names no host in this case.'
      },
      what: {
        prompt: 'What happened?',
        options: [
          { id: 'a', label: 'A helpdesk engineer cleared five forgotten passwords together during a quiet hour, with the helpdesk queue empty.' },
          { id: 'b', label: 'Five colleagues each reset their own password shortly after logging in, as the expiry policy requires.' },
          { id: 'c', label: 'A session on sec-win-05 attributed to kpatel reset five other accounts\u2019 passwords in two minutes thirty-seven seconds using the self-service method, then authenticated as asmith and jdoe from 203.0.113.45 and opened a command shell inside the asmith session.' },
          { id: 'd', label: 'An estate-wide password-expiry policy fired and forced five users to reset at the same time.' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'The assessment has to carry the mechanism (self-service resets used against other accounts), the ' +
          'subject (an account with no delegated right), the count and window, and the outcome (two of the five ' +
          'used, one session opened a shell). Every alternative in this question needs the subject or the method ' +
          'to be different from what the records state \u2014 and an assessment that only says "passwords were ' +
          'reset" would fit all of them.'
      },
      why: {
        prompt: 'Why is it suspicious? Select every reason that holds.',
        options: [
          { id: 'a', label: 'kpatel holds no password-reset delegation and has reset nothing in 90 days' },
          { id: 'b', label: 'The method on all five records is ADSelfReset, which can only reset the subject\u2019s own password' },
          { id: 'c', label: 'Five accounts were reset by one session in two minutes thirty-seven seconds' },
          { id: 'd', label: 'Users do help each other with passwords when they cannot remember them' },
          { id: 'e', label: 'Two of the five accounts then logged on from 203.0.113.45, the address that opened the session' },
          { id: 'f', label: 'No helpdesk ticket matches any of the five events, and the queue was empty' }
        ],
        correct: ['a', 'b', 'c', 'e', 'f'],
        xp: 10,
        explain:
          'Five of these six are anchored to a record or a fact you were given: an absent entitlement, a method ' +
          'that cannot do what happened, a rate, a source address that recurs across three sessions, and an ' +
          'absent ticket. Only option D is an assumption, and it is the one that would make this a support ' +
          'call \u2014 people who help each other do not do it from an external address, five times, without a ' +
          'ticket, using a method that cannot legally reset a colleague\u2019s password.'
      },
      confidence: {
        prompt: 'Analyst confidence in this assessment',
        options: [
          { id: 'a', label: 'Low' },
          { id: 'b', label: 'Medium' },
          { id: 'c', label: 'High' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'The reset records, the delegation data, the helpdesk records and the subsequent logons all agree, and ' +
          'they agree in one order: mint, spend. The open questions \u2014 where the initial access to ' +
          'kpatel\u2019s session came from, and whether the three unused accounts were reached from elsewhere \u2014 ' +
          'are scoping questions about a case whose core is already established.'
      },
      actions: {
        prompt: 'Recommended next actions. Select the three that follow from this assessment.',
        options: [
          { id: 'a', label: 'Force a password change on all five reset accounts, invalidate their cached credentials and revoke active sessions \u2014 starting with asmith and jdoe' },
          { id: 'b', label: 'Reset kpatel\u2019s credentials and revoke its session, and review every other action taken in that session' },
          { id: 'c', label: 'Hunt the domain for every 4724 whose subject holds no reset delegation, and for accounts authenticating soon after a reset' },
          { id: 'd', label: 'Rebuild sec-win-05 and every workstation in the marketing group' },
          { id: 'e', label: 'Remove the Helpdesk group\u2019s password-reset delegation while this is investigated' },
          { id: 'f', label: 'Ask the five users whether they needed their passwords resetting that morning' }
        ],
        correct: ['a', 'b', 'c'],
        xp: 10,
        explain:
          'All five accounts were changed by somebody else, so all five need new credentials \u2014 asmith and ' +
          'jdoe first, because they are the two with demonstrated use, with cached credentials and sessions ' +
          'revoked so an old token cannot outlast the change. The session the resets came from is still the ' +
          'attacker\u2019s, so kpatel is reset and its session reviewed. And the pattern is deployable today: ' +
          'alert on 4724 by subjects without delegation. Options D and F are wrong in opposite directions, and ' +
          'E removes the legitimate process that would normally be handling these requests.'
      }
    },

    reasoning: {
      prompt: 'Which three pieces of evidence most strongly support your assessment? Select exactly three.',
      options: [
        { id: 'r1', label: 'kpatel is a member of Domain Users and Marketing-Read', key: false },
        { id: 'r2', label: 'Five Event 4724 records on sec-win-05 between 08:04:37 and 08:07:14, all with subject kpatel and method ADSelfReset \u2014 a method that can only reset the subject\u2019s own password', key: true },
        { id: 'r3', label: 'Four other users were active on the estate during the same hour', key: false },
        { id: 'r4', label: 'kpatel holds no password-reset delegation, has reset nothing in 90 days, and has never logged on from 203.0.113.45', key: true },
        { id: 'r5', label: 'Event 4672 appears on this host several times a day', key: false },
        { id: 'r6', label: 'Event 4624 for asmith at 08:10:26 and for jdoe at 08:12:03, both from 203.0.113.45, followed by cmd.exe inside the asmith session at 08:14:19', key: true },
        { id: 'r7', label: 'The workstation has the standard corporate build', key: false }
      ],
      correctCount: 3,
      xp: 10,
      explain:
        'The three that carry the finding are the resets themselves, the entitlement that makes them impossible, ' +
        'and the logons that show the credentials were spent \u2014 mechanism, authority and result. Two of them ' +
        'come from different sources on the host, which is what makes them corroborate rather than repeat. ' +
        'Group membership in isolation, estate busyness, routine privilege events and the software build are ' +
        'background: true, and not load-bearing.'
    },

    /* mirrored verbatim from new.scenario — the dotted keys are kept as written
       there, because this block is the record of what the case is actually made of */
    ground_truth: {
      password_reset_events: 5,
      distinct_accounts_with_password_reset: 5,
      'successful_logons_for_asmith_from_203.0.113.45': 1,
      'successful_logons_for_jdoe_from_203.0.113.45': 1,
      target_host: 'sec-win-05',
      event_ids_present: [4624, 4688, 4724]
    },

    ranking: [
      { min: 90, rank: 'Lead Intelligence Analyst', note: 'You produced defensible intelligence, not just correct answers.' },
      { min: 75, rank: 'Threat Intelligence Analyst', note: 'Strong correlation and a defensible judgment.' },
      { min: 55, rank: 'Junior CTI Investigator', note: 'You found the resets and explained them. Tighten the correlation and the reporting.' },
      { min: 0, rank: 'Case Officer Trainee', note: 'Re-run the case. Read the five 4724 records as one burst, then read the two logons that follow.' }
    ],

    assist: {
      nudge: { label: 'Nudge', mult: 0.85, text: 'Look at the method field on those five records. Ask whether that method is even capable of what happened.' },
      hint: { label: 'Analyst Hint', mult: 0.7, text: 'One record shows who may reset passwords here. Another shows five resets at once. A third shows two of those accounts being used afterwards.' },
      explain: { label: 'Explain', mult: 0.5, text: 'A session for kpatel from 203.0.113.45 — an account with no password-reset delegation and no reset in 90 days — logged on to sec-win-05 at 08:01:44. Between 08:04:37 and 08:07:14 it produced five Event 4724 records resetting jdoe, asmith, mchen, rneuman and svega, all with method ADSelfReset, which can only ever change the subject\u2019s own password. At 08:10:26 asmith authenticated from the same address, at 08:12:03 so did jdoe, and at 08:14:19 cmd.exe was opened inside the asmith session. The mechanism is Password Guessing: Password Reset, T1110.001 — credential access — followed by Valid Accounts (T1078). Force a password change on all five accounts starting with the two used, reset kpatel, and alert on 4724 by subjects holding no delegation.' }
    }
  });
})();