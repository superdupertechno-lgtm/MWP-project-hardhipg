const express = require('express');
const fs = require('fs');
const { db } = require('../db');
const v = require('../lib/validate');
const { verifyCsrf, requireAuth } = require('../lib/middleware');
const { handleAvatarUpload, looksLikeImage, removeAvatarFile } = require('../lib/upload');

const router = express.Router();
const PAGE_SIZE = 12;

const countPublic = db.prepare(`
  SELECT COUNT(*) AS n FROM users
  WHERE is_public = 1
    AND (@q = '' OR username LIKE @like ESCAPE '\\' OR display_name LIKE @like ESCAPE '\\'
         OR headline LIKE @like ESCAPE '\\' OR location LIKE @like ESCAPE '\\')
`);
const listPublic = db.prepare(`
  SELECT username, display_name, headline, location, avatar FROM users
  WHERE is_public = 1
    AND (@q = '' OR username LIKE @like ESCAPE '\\' OR display_name LIKE @like ESCAPE '\\'
         OR headline LIKE @like ESCAPE '\\' OR location LIKE @like ESCAPE '\\')
  ORDER BY created_at DESC, id DESC
  LIMIT @limit OFFSET @offset
`);
const findByUsername = db.prepare('SELECT * FROM users WHERE username = ?');
const findById = db.prepare('SELECT * FROM users WHERE id = ?');
const updateProfile = db.prepare(`
  UPDATE users SET display_name = @display_name, headline = @headline, bio = @bio,
    location = @location, website = @website, github = @github, linkedin = @linkedin,
    avatar = @avatar, is_public = @is_public, updated_at = @now
  WHERE id = @id
`);

// ---------- Directory ----------

router.get('/', (req, res) => {
  const q = v.str(req.query.q).slice(0, 50);
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const params = { q, like: `%${v.likeEscape(q)}%` };

  const total = countPublic.get(params).n;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const people = listPublic.all({
    ...params,
    limit: PAGE_SIZE,
    offset: (Math.min(page, pages) - 1) * PAGE_SIZE,
  });

  res.render('index', { title: null, q, people, total, page: Math.min(page, pages), pages });
});

// ---------- Edit own profile (declared before /u/:username routes for clarity) ----------

function renderEdit(res, status, user, values, errors) {
  res.status(status).render('edit-profile', { title: 'Edit profile', profile: user, values, errors });
}

router.get('/profile/edit', requireAuth, (req, res) => {
  const user = findById.get(req.user.id);
  renderEdit(res, 200, user, user, {});
});

router.post('/profile/edit', requireAuth, handleAvatarUpload, verifyCsrf, (req, res, next) => {
  try {
    const user = findById.get(req.user.id);
    const body = req.body || {};

    const values = {
      display_name: v.str(body.display_name),
      headline: v.str(body.headline),
      bio: typeof body.bio === 'string' ? body.bio.replace(/\r\n/g, '\n').trim() : '',
      location: v.str(body.location),
      website: v.str(body.website),
      github: v.str(body.github),
      linkedin: v.str(body.linkedin),
      is_public: body.is_public === 'on' ? 1 : 0,
    };

    const errors = {};
    if (!values.display_name || values.display_name.length > 50)
      errors.display_name = 'Enter a name up to 50 characters.';
    if (values.headline.length > 80) errors.headline = 'Keep this under 80 characters.';
    if (values.bio.length > 400) errors.bio = 'Keep your bio under 400 characters.';
    if (values.location.length > 60) errors.location = 'Keep this under 60 characters.';

    const website = v.url(values.website);
    if (website === null) errors.website = 'Enter a valid web address, like example.com.';
    const github = v.github(values.github);
    if (github === null) errors.github = 'Enter your GitHub username.';
    const linkedin = v.linkedin(values.linkedin);
    if (linkedin === null) errors.linkedin = 'Enter your LinkedIn profile name.';

    // Avatar: a new upload wins over "remove".
    let avatar = user.avatar;
    let newUpload = null;
    if (req.uploadError) {
      errors.avatar = req.uploadError;
    } else if (req.file) {
      if (looksLikeImage(req.file.path)) newUpload = req.file.filename;
      else errors.avatar = 'That file is not a valid PNG, JPG, or WebP image.';
    }

    if (Object.keys(errors).length) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return renderEdit(res, 422, user, values, errors);
    }

    if (newUpload) {
      removeAvatarFile(user.avatar);
      avatar = newUpload;
    } else if (body.remove_avatar === 'on') {
      removeAvatarFile(user.avatar);
      avatar = null;
    }

    updateProfile.run({
      ...values,
      website,
      github,
      linkedin,
      avatar,
      now: Date.now(),
      id: user.id,
    });

    req.flash('success', 'Profile saved.');
    res.redirect(`/u/${user.username}`);
  } catch (err) {
    if (req.file) fs.unlink(req.file.path, () => {});
    next(err);
  }
});

// ---------- Public profile ----------

router.get('/u/:username', (req, res) => {
  const profile = findByUsername.get(req.params.username);
  const isOwner = Boolean(profile && req.user && req.user.id === profile.id);

  // Private profiles look identical to missing ones for everyone but the owner.
  if (!profile || (!profile.is_public && !isOwner)) {
    return res.status(404).render('error', {
      title: 'Not found',
      heading: 'No profile here',
      message: 'This username does not exist, or its owner has made it private.',
    });
  }

  res.render('profile', { title: profile.display_name, profile, isOwner });
});

module.exports = router;
