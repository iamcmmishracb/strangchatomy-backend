const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');

// Admin authentication
const adminProtect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization?.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    if (!token) return res.status(401).json({ success: false, message: 'Admin token required' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.id).select('-password');
    if (!admin || !admin.isActive) return res.status(401).json({ success: false, message: 'Admin not found' });

    req.admin = admin;
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'Admin token invalid' });
  }
};

// Superadmin only (for LE exports)
const superAdminOnly = async (req, res, next) => {
  if (req.admin?.role !== 'superadmin') {
    return res.status(403).json({ success: false, message: 'Superadmin access required for this operation' });
  }
  next();
};

module.exports = { adminProtect, superAdminOnly };
