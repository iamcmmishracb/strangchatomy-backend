// App Key middleware - protects public API endpoints from unauthorized access
//
// DEVELOPMENT (NODE_ENV=development):
//   App key check is SKIPPED so you can test without updating the Flutter app.
//
// PRODUCTION (NODE_ENV=production):
//   Every request to /api/sessions/* MUST include header:
//   X-App-Key: <value of APP_SECRET in .env>

const appKeyProtect = (req, res, next) => {
  // Skip check in development - allows Flutter app to work without X-App-Key
  if (!process.env.NODE_ENV || process.env.NODE_ENV === 'development') {
    return next();
  }

  const appKey = req.headers['x-app-key'];

  if (!appKey) {
    return res.status(401).json({
      success: false,
      message: 'Missing X-App-Key header'
    });
  }

  if (appKey !== process.env.APP_SECRET) {
    return res.status(403).json({
      success: false,
      message: 'Invalid app key'
    });
  }

  next();
};

module.exports = { appKeyProtect };
