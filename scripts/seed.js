// Optional: adds a few demo profiles so the home page isn't empty.  Run: npm run seed
// Every demo account uses the password "demo-password-1".
const bcrypt = require('bcryptjs');
const { db } = require('../db');

const people = [
  ['grace_h', 'Grace Hopper', 'Compiler pioneer', 'Wrote the first compiler and made "debugging" a word people use.\nNow mostly retired, still opinionated about nanoseconds.', 'New York', 'example.com', 'ghopper'],
  ['linus_t', 'Linus T', 'Kernel maintainer', 'I make operating systems and occasionally strong statements.', 'Portland', '', 'torvalds'],
  ['ada_l', 'Ada Lovelace', 'Analyst and writer', 'Notes on the Analytical Engine, mostly. Poetical science is the goal.', 'London', '', ''],
  ['margaret_h', 'Margaret Hamilton', 'Software engineer', '', 'Boston', '', ''],
  ['katherine_j', 'Katherine Johnson', 'Mathematician', 'Trajectories, checked by hand.', 'Hampton', '', ''],
  ['tim_bl', 'Tim B-L', 'Web inventor', '', 'Geneva', 'example.org', ''],
];

const hash = bcrypt.hashSync('demo-password-1', 12);
const insert = db.prepare(`
  INSERT OR IGNORE INTO users
    (username, email, password_hash, display_name, headline, bio, location, website, github, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

let added = 0;
people.forEach(([username, name, headline, bio, location, website, github], i) => {
  const now = Date.now() - (people.length - i) * 3600 * 1000;
  const site = website ? `https://${website}/` : '';
  added += insert.run(username, `${username}@example.com`, hash, name, headline, bio, location, site, github, now, now).changes;
});
console.log(`Added ${added} demo profile(s). Log in as any of them with password "demo-password-1".`);
