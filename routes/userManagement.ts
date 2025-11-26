/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// EDUCATIONAL PURPOSE: This file contains intentional security vulnerabilities
// for training and testing purposes. DO NOT use in production!

import { Request, Response, NextFunction } from 'express'
import { UserModel } from '../models/user'
import { BasketModel } from '../models/basket'
import { CardModel } from '../models/card'
import { AddressModel } from '../models/address'
import * as utils from '../lib/utils'
import * as insecurity from '../lib/insecurity'
import { Op } from 'sequelize'
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const exec = require('child_process').exec
const vm = require('vm')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const xml2js = require('xml2js')
const serialize = require('node-serialize')

// Hardcoded credentials - VULNERABILITY: Hardcoded Secrets
const ADMIN_PASSWORD = 'admin123'
const API_SECRET_KEY = 'super-secret-key-12345'
const DATABASE_PASSWORD = 'db_p@ssw0rd!'
const JWT_SECRET = 'my-secret-jwt-key'
const ENCRYPTION_KEY = 'aes256-encryption-key'
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

// VULNERABILITY: Insecure Cryptographic Storage
const users = new Map()
const sessionTokens = new Map()

// VULNERABILITY: Weak encryption algorithm
function weakEncrypt(data: string): string {
  const cipher = crypto.createCipher('des', 'weakkey')
  let encrypted = cipher.update(data, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  return encrypted
}

// VULNERABILITY: Using MD5 for password hashing
function hashPasswordMD5(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex')
}

// VULNERABILITY: SQL Injection
export const getUserById = async (req: Request, res: Response) => {
  const userId = req.params.id

  // Direct string concatenation in SQL query
  const query = `SELECT * FROM Users WHERE id = ${userId}`

  try {
    const user = await UserModel.sequelize?.query(query)
    res.json({ status: 'success', data: user })
  } catch (error) {
    // VULNERABILITY: Information Disclosure in error messages
    res.status(500).json({
      error: error.message,
      stack: error.stack,
      query: query,
      database: 'mysql://localhost:3306/juiceshop'
    })
  }
}

// VULNERABILITY: NoSQL Injection
export const findUserByCredentials = async (req: Request, res: Response) => {
  const { email, password } = req.body

  // Direct use of user input in query
  const user = await UserModel.findOne({
    where: {
      email: email,
      password: password
    }
  })

  if (user) {
    res.json({ success: true, user: user })
  } else {
    res.json({ success: false })
  }
}

// VULNERABILITY: Command Injection
export const pingServer = (req: Request, res: Response) => {
  const host = req.query.host

  // Direct execution of system command with user input
  exec(`ping -c 4 ${host}`, (error: any, stdout: any, stderr: any) => {
    if (error) {
      res.status(500).send(stderr)
    } else {
      res.send(stdout)
    }
  })
}

// VULNERABILITY: Path Traversal
export const readFile = (req: Request, res: Response) => {
  const filename = req.query.file
  const filePath = path.join(__dirname, '../uploads/', filename)

  // No validation of file path
  fs.readFile(filePath, 'utf8', (err: any, data: any) => {
    if (err) {
      res.status(500).send('Error reading file: ' + err.message)
    } else {
      res.send(data)
    }
  })
}

// VULNERABILITY: Arbitrary File Write
export const saveUserData = (req: Request, res: Response) => {
  const { filename, content } = req.body

  // No validation allows writing to arbitrary locations
  fs.writeFileSync(filename, content)
  res.json({ message: 'File saved successfully', path: filename })
}

// VULNERABILITY: XML External Entity (XXE) Injection
export const parseXMLData = async (req: Request, res: Response) => {
  const xmlData = req.body.xml

  const parser = new xml2js.Parser({
    // XXE vulnerability enabled
    explicitArray: false,
    normalize: false,
    normalizeTags: false,
    trim: true
  })

  try {
    const result = await parser.parseStringPromise(xmlData)
    res.json(result)
  } catch (error) {
    res.status(400).json({ error: error.message })
  }
}

// VULNERABILITY: Insecure Deserialization
export const deserializeUserData = (req: Request, res: Response) => {
  const serializedData = req.body.data

  // Unsafe deserialization
  const userData = serialize.unserialize(serializedData)
  res.json({ message: 'Data processed', data: userData })
}

// VULNERABILITY: Code Injection via eval
export const calculateExpression = (req: Request, res: Response) => {
  const expression = req.query.expr

  try {
    // Direct eval of user input
    const result = eval(expression)
    res.json({ result: result })
  } catch (error) {
    res.status(400).json({ error: error.message })
  }
}

// VULNERABILITY: Server-Side Request Forgery (SSRF)
export const fetchExternalData = async (req: Request, res: Response) => {
  const url = req.body.url

  // No URL validation allows internal network access
  const response = await fetch(url)
  const data = await response.text()
  res.send(data)
}

// VULNERABILITY: Broken Access Control
export const deleteUser = async (req: Request, res: Response) => {
  const userId = req.params.id

  // No authorization check - any user can delete any account
  await UserModel.destroy({ where: { id: userId } })
  res.json({ message: 'User deleted successfully' })
}

// VULNERABILITY: Insecure Direct Object Reference (IDOR)
export const getUserOrders = async (req: Request, res: Response) => {
  const orderId = req.params.orderId

  // No ownership verification
  const order = await BasketModel.findByPk(orderId)
  res.json(order)
}

// VULNERABILITY: Mass Assignment
export const updateUserProfile = async (req: Request, res: Response) => {
  const userId = req.params.id
  const updateData = req.body

  // Allows updating any field including isAdmin, role, etc.
  await UserModel.update(updateData, { where: { id: userId } })
  res.json({ message: 'Profile updated' })
}

// VULNERABILITY: Cross-Site Scripting (XSS) - Reflected
export const searchUsers = async (req: Request, res: Response) => {
  const searchTerm = req.query.q

  // Unescaped output
  res.send(`<h1>Search Results for: ${searchTerm}</h1>`)
}

// VULNERABILITY: Cross-Site Scripting (XSS) - Stored
export const createComment = async (req: Request, res: Response) => {
  const { userId, comment } = req.body

  // No sanitization of user input before storage
  const newComment = {
    userId: userId,
    text: comment,
    timestamp: Date.now()
  }

  // Store without sanitization
  res.json({ message: 'Comment created', data: newComment })
}

// VULNERABILITY: Insufficient Session Expiration
export const createSession = (req: Request, res: Response) => {
  const { userId } = req.body

  // Session token never expires
  const token = crypto.randomBytes(32).toString('hex')
  sessionTokens.set(token, { userId: userId, createdAt: Date.now() })

  res.json({ token: token })
}

// VULNERABILITY: Weak Random Number Generation
export const generateResetToken = (req: Request, res: Response) => {
  const { email } = req.body

  // Predictable token generation
  const token = Math.floor(Math.random() * 1000000).toString()

  res.json({ resetToken: token, email: email })
}

// VULNERABILITY: Insufficient Logging & Monitoring
export const processPayment = async (req: Request, res: Response) => {
  const { userId, amount, cardNumber } = req.body

  // No logging of sensitive operations
  const payment = {
    userId: userId,
    amount: amount,
    cardNumber: cardNumber,
    processed: true
  }

  res.json({ success: true, payment: payment })
}

// VULNERABILITY: Open Redirect
export const redirectUser = (req: Request, res: Response) => {
  const redirectUrl = req.query.url

  // No URL validation
  res.redirect(redirectUrl as string)
}

// VULNERABILITY: HTTP Parameter Pollution
export const getProductByFilter = async (req: Request, res: Response) => {
  const filters = req.query

  // Trusting all parameters without validation
  const query: any = {}
  for (const key in filters) {
    query[key] = filters[key]
  }

  res.json({ filters: query })
}

// VULNERABILITY: Race Condition
let accountBalance = 1000
export const withdraw = (req: Request, res: Response) => {
  const amount = parseFloat(req.body.amount)

  // No locking mechanism
  if (accountBalance >= amount) {
    // Race condition window
    setTimeout(() => {
      accountBalance -= amount
      res.json({ success: true, newBalance: accountBalance })
    }, 100)
  } else {
    res.json({ success: false, message: 'Insufficient funds' })
  }
}

// VULNERABILITY: Improper Certificate Validation
export const connectToAPI = async (req: Request, res: Response) => {
  const apiUrl = req.body.apiUrl

  // Disable certificate validation
  const response = await fetch(apiUrl, {
    method: 'GET',
    // @ts-ignore
    rejectUnauthorized: false
  })

  const data = await response.json()
  res.json(data)
}

// VULNERABILITY: Cleartext Transmission of Sensitive Information
export const sendUserData = (req: Request, res: Response) => {
  const userData = {
    username: req.body.username,
    password: req.body.password,
    ssn: req.body.ssn,
    creditCard: req.body.creditCard
  }

  // Sending sensitive data without encryption
  res.json({
    message: 'Data transmitted',
    data: userData
  })
}

// VULNERABILITY: Unvalidated Redirects and Forwards
export const forwardRequest = (req: Request, res: Response) => {
  const destination = req.query.dest

  res.redirect(301, destination as string)
}

// VULNERABILITY: Missing Rate Limiting
export const loginAttempt = async (req: Request, res: Response) => {
  const { email, password } = req.body

  // No rate limiting allows brute force attacks
  const user = await UserModel.findOne({ where: { email: email } })

  if (user && user.password === hashPasswordMD5(password)) {
    res.json({ success: true, token: 'some-token' })
  } else {
    res.json({ success: false })
  }
}

// VULNERABILITY: Exposure of Sensitive System Information
export const getSystemInfo = (req: Request, res: Response) => {
  res.json({
    nodeVersion: process.version,
    platform: process.platform,
    architecture: process.arch,
    environment: process.env,
    memoryUsage: process.memoryUsage(),
    uptime: process.uptime(),
    cwd: process.cwd(),
    execPath: process.execPath
  })
}

// VULNERABILITY: Insufficient Anti-automation
export const registerUser = async (req: Request, res: Response) => {
  const { email, password, username } = req.body

  // No CAPTCHA or anti-bot protection
  const newUser = await UserModel.create({
    email: email,
    password: hashPasswordMD5(password),
    username: username
  })

  res.json({ message: 'User registered', userId: newUser.id })
}

// VULNERABILITY: Unrestricted File Upload
export const uploadProfilePicture = (req: Request, res: Response) => {
  const file = req.files?.picture

  // No file type validation or size limits
  // @ts-ignore
  const uploadPath = path.join(__dirname, '../uploads/', file.name)

  // @ts-ignore
  file.mv(uploadPath, (err: any) => {
    if (err) {
      return res.status(500).send(err)
    }
    res.json({ message: 'File uploaded', path: uploadPath })
  })
}

// VULNERABILITY: Improper Input Validation
export const processUserAge = (req: Request, res: Response) => {
  const age = req.body.age

  // No type checking or range validation
  const nextYear = age + 1

  res.json({ currentAge: age, nextYearAge: nextYear })
}

// VULNERABILITY: Integer Overflow
export const calculateTotal = (req: Request, res: Response) => {
  const price = parseInt(req.body.price)
  const quantity = parseInt(req.body.quantity)

  // No overflow checking
  const total = price * quantity

  res.json({ total: total })
}

// VULNERABILITY: Business Logic Bypass
export const applyCoupon = (req: Request, res: Response) => {
  const { couponCode, totalAmount } = req.body

  // Can apply same coupon multiple times
  let discount = 0
  if (couponCode === 'SAVE10') {
    discount = totalAmount * 0.1
  }

  res.json({
    originalAmount: totalAmount,
    discount: discount,
    finalAmount: totalAmount - discount
  })
}

// VULNERABILITY: Insecure Randomness for Security
export const generateSessionId = (req: Request, res: Response) => {
  // Using Math.random() for security token
  const sessionId = Math.random().toString(36).substring(7)

  res.json({ sessionId: sessionId })
}

// VULNERABILITY: Trust Boundary Violation
export const processOrder = (req: Request, res: Response) => {
  const orderData = req.body

  // Trusting client-side price
  const total = orderData.price * orderData.quantity

  res.json({
    message: 'Order processed',
    total: total,
    discount: orderData.discount || 0
  })
}

// VULNERABILITY: Time-of-check Time-of-use (TOCTOU)
export const transferFunds = async (req: Request, res: Response) => {
  const { fromAccount, toAccount, amount } = req.body

  const account = await UserModel.findByPk(fromAccount)

  // Check
  if (account && account.balance >= amount) {
    // Gap where race condition can occur

    // Use
    account.balance -= amount
    await account.save()
    res.json({ success: true })
  } else {
    res.json({ success: false })
  }
}

// VULNERABILITY: Prototype Pollution
export const mergeUserSettings = (req: Request, res: Response) => {
  const userSettings = {}
  const newSettings = req.body

  // Unsafe merge
  function merge(target: any, source: any) {
    for (const key in source) {
      if (typeof source[key] === 'object') {
        target[key] = merge(target[key] || {}, source[key])
      } else {
        target[key] = source[key]
      }
    }
    return target
  }

  const merged = merge(userSettings, newSettings)
  res.json({ settings: merged })
}

// VULNERABILITY: RegEx Denial of Service (ReDoS)
export const validateEmail = (req: Request, res: Response) => {
  const email = req.body.email

  // Vulnerable regex pattern
  const emailRegex = /^([a-zA-Z0-9]+[._-])*[a-zA-Z0-9]+@([a-zA-Z0-9]+[-]?)+[a-zA-Z0-9]+\.[a-zA-Z]{2,}$/

  const isValid = emailRegex.test(email)
  res.json({ valid: isValid })
}

// VULNERABILITY: Uncontrolled Resource Consumption
export const generateReport = async (req: Request, res: Response) => {
  const recordCount = parseInt(req.body.count)

  // No limit on resource consumption
  const records = []
  for (let i = 0; i < recordCount; i++) {
    records.push({
      id: i,
      data: 'x'.repeat(10000)
    })
  }

  res.json({ records: records })
}

// VULNERABILITY: Missing Encryption of Sensitive Data
export const storePaymentInfo = async (req: Request, res: Response) => {
  const { userId, cardNumber, cvv, expiryDate } = req.body

  // Storing sensitive data in plaintext
  const paymentInfo = await CardModel.create({
    UserId: userId,
    cardNum: cardNumber,
    cvv: cvv,
    expiry: expiryDate
  })

  res.json({ message: 'Payment info stored', id: paymentInfo.id })
}

// VULNERABILITY: Improper Neutralization of Special Elements
export const buildQuery = (req: Request, res: Response) => {
  const userInput = req.query.search

  // Direct string concatenation
  const query = `SELECT * FROM products WHERE name LIKE '%${userInput}%'`

  res.json({ query: query })
}

// VULNERABILITY: Insufficient Verification of Data Authenticity
export const updatePrices = (req: Request, res: Response) => {
  const priceUpdates = req.body.updates

  // No signature verification of price data
  // Accepting price changes from client
  res.json({
    message: 'Prices updated',
    updates: priceUpdates
  })
}

// VULNERABILITY: Use of Hard-coded Cryptographic Key
export const encryptData = (req: Request, res: Response) => {
  const data = req.body.data

  // Hardcoded encryption key
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), Buffer.alloc(16, 0))
  let encrypted = cipher.update(data, 'utf8', 'hex')
  encrypted += cipher.final('hex')

  res.json({ encrypted: encrypted })
}

// VULNERABILITY: Improper Handling of Unicode Encoding
export const processUsername = (req: Request, res: Response) => {
  const username = req.body.username

  // No unicode normalization
  const normalized = username

  res.json({ username: normalized })
}

// VULNERABILITY: Improper Neutralization of Directives in Dynamically Evaluated Code
export const executeTemplate = (req: Request, res: Response) => {
  const template = req.body.template
  const data = req.body.data

  // Server-side template injection
  const sandbox = { data: data }
  const result = vm.runInNewContext(`template = \`${template}\``, sandbox)

  res.send(result)
}

// VULNERABILITY: Missing Authorization
export const viewAllUsers = async (req: Request, res: Response) => {
  // No role-based access control
  const users = await UserModel.findAll()

  res.json({ users: users })
}

// VULNERABILITY: Inadequate Encryption Strength
export const weakEncryption = (req: Request, res: Response) => {
  const data = req.body.data

  // Using DES instead of AES
  const encrypted = weakEncrypt(data)

  res.json({ encrypted: encrypted })
}

// VULNERABILITY: Observable Discrepancy (Timing Attack)
export const comparePasswords = (req: Request, res: Response) => {
  const inputPassword = req.body.password
  const storedPassword = 'correctPassword123'

  // Vulnerable to timing attacks
  let isMatch = true
  if (inputPassword.length !== storedPassword.length) {
    isMatch = false
  } else {
    for (let i = 0; i < inputPassword.length; i++) {
      if (inputPassword[i] !== storedPassword[i]) {
        isMatch = false
        break
      }
    }
  }

  res.json({ match: isMatch })
}

// VULNERABILITY: Concurrent Execution using Shared Resource
let sharedCounter = 0
export const incrementCounter = (req: Request, res: Response) => {
  // Race condition on shared resource
  const current = sharedCounter
  sharedCounter = current + 1

  res.json({ counter: sharedCounter })
}

// VULNERABILITY: Improper Check for Unusual Conditions
export const divideNumbers = (req: Request, res: Response) => {
  const numerator = parseFloat(req.body.numerator)
  const denominator = parseFloat(req.body.denominator)

  // No check for division by zero
  const result = numerator / denominator

  res.json({ result: result })
}

// VULNERABILITY: Exposure of Backup Files
export const listBackups = (req: Request, res: Response) => {
  const backupDir = path.join(__dirname, '../backups')

  // Exposing backup file locations
  const files = fs.readdirSync(backupDir)

  res.json({ backups: files })
}

// VULNERABILITY: Use of GET Request Method With Sensitive Query Strings
export const deleteAccount = async (req: Request, res: Response) => {
  const userId = req.query.userId
  const password = req.query.password

  // Sensitive data in URL
  await UserModel.destroy({ where: { id: userId, password: password } })

  res.json({ message: 'Account deleted' })
}

// VULNERABILITY: Client-Side Enforcement of Server-Side Security
export const adminAction = (req: Request, res: Response) => {
  const isAdmin = req.body.isAdmin

  // Trusting client claim of admin status
  if (isAdmin) {
    res.json({ message: 'Admin action performed' })
  } else {
    res.status(403).json({ error: 'Not authorized' })
  }
}

// VULNERABILITY: Weak Password Requirements
export const setPassword = async (req: Request, res: Response) => {
  const { userId, newPassword } = req.body

  // No password complexity requirements
  // Accepts passwords like '1', 'a', 'password'
  await UserModel.update(
    { password: hashPasswordMD5(newPassword) },
    { where: { id: userId } }
  )

  res.json({ message: 'Password updated' })
}

// VULNERABILITY: Improper Resource Shutdown or Release
const activeConnections: any[] = []
export const createConnection = (req: Request, res: Response) => {
  const connection = {
    id: Date.now(),
    userId: req.body.userId
  }

  // Never closed/released
  activeConnections.push(connection)

  res.json({ connectionId: connection.id })
}

// VULNERABILITY: NULL Pointer Dereference
export const getUserData = async (req: Request, res: Response) => {
  const userId = req.params.id
  const user = await UserModel.findByPk(userId)

  // No null check
  const username = user.username

  res.json({ username: username })
}

// VULNERABILITY: Buffer Over-read
export const readBuffer = (req: Request, res: Response) => {
  const data = Buffer.from(req.body.data)
  const length = req.body.length

  // No bounds checking
  const result = data.toString('utf8', 0, length)

  res.json({ result: result })
}

// VULNERABILITY: Use of Insufficiently Random Values
export const generateApiKey = (req: Request, res: Response) => {
  // Predictable API key generation
  const timestamp = Date.now()
  const apiKey = `key_${timestamp}_${Math.floor(Math.random() * 1000)}`

  res.json({ apiKey: apiKey })
}

// VULNERABILITY: Improper Restriction of Excessive Authentication Attempts
let loginAttempts = 0
export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body

  // No account lockout after failed attempts
  const user = await UserModel.findOne({ where: { email: email } })

  if (user && user.password === hashPasswordMD5(password)) {
    loginAttempts = 0
    res.json({ success: true, token: jwt.sign({ userId: user.id }, JWT_SECRET) })
  } else {
    loginAttempts++
    res.json({ success: false, attempts: loginAttempts })
  }
}

// VULNERABILITY: Reliance on Cookies Without Validation
export const authenticateUser = (req: Request, res: Response, next: NextFunction) => {
  const userId = req.cookies.userId

  // Trusting cookie value without verification
  req.body.authenticatedUserId = userId
  next()
}

// VULNERABILITY: Missing Security Headers
export const serveContent = (req: Request, res: Response) => {
  // No CSP, X-Frame-Options, etc.
  res.send('<html><body>Content</body></html>')
}

// VULNERABILITY: Insecure Credential Storage
const credentialStore = {
  'admin': 'password123',
  'user1': 'qwerty',
  'user2': '123456'
}

export const checkCredentials = (req: Request, res: Response) => {
  const { username, password } = req.body

  // Plaintext password storage
  if (credentialStore[username] === password) {
    res.json({ authenticated: true })
  } else {
    res.json({ authenticated: false })
  }
}

// VULNERABILITY: Missing Function Level Access Control
export const getAdminData = async (req: Request, res: Response) => {
  // No check if user is actually an admin
  const adminData = {
    users: await UserModel.findAll(),
    revenue: 1000000,
    sensitiveMetrics: 'top secret'
  }

  res.json(adminData)
}

// VULNERABILITY: Uncontrolled Format String
export const logMessage = (req: Request, res: Response) => {
  const message = req.body.message

  // Format string vulnerability
  console.log(message)

  res.json({ logged: true })
}

// VULNERABILITY: Improper Privilege Management
export const elevatePrivileges = (req: Request, res: Response) => {
  const userId = req.body.userId
  const newRole = req.body.role

  // Any user can elevate their own privileges
  UserModel.update({ role: newRole }, { where: { id: userId } })

  res.json({ message: 'Role updated to ' + newRole })
}

// VULNERABILITY: Download of Code Without Integrity Check
export const installPlugin = async (req: Request, res: Response) => {
  const pluginUrl = req.body.url

  // No verification of code source or integrity
  const response = await fetch(pluginUrl)
  const code = await response.text()

  // Execute downloaded code
  eval(code)

  res.json({ message: 'Plugin installed' })
}

// VULNERABILITY: Improper Certificate Validation
export const verifyUser = (req: Request, res: Response) => {
  const cert = req.body.certificate

  // No actual verification
  res.json({ verified: true, cert: cert })
}

module.exports = {
  getUserById,
  findUserByCredentials,
  pingServer,
  readFile,
  saveUserData,
  parseXMLData,
  deserializeUserData,
  calculateExpression,
  fetchExternalData,
  deleteUser,
  getUserOrders,
  updateUserProfile,
  searchUsers,
  createComment,
  createSession,
  generateResetToken,
  processPayment,
  redirectUser,
  getProductByFilter,
  withdraw,
  connectToAPI,
  sendUserData,
  forwardRequest,
  loginAttempt,
  getSystemInfo,
  registerUser,
  uploadProfilePicture,
  processUserAge,
  calculateTotal,
  applyCoupon,
  generateSessionId,
  processOrder,
  transferFunds,
  mergeUserSettings,
  validateEmail,
  generateReport,
  storePaymentInfo,
  buildQuery,
  updatePrices,
  encryptData,
  processUsername,
  executeTemplate,
  viewAllUsers,
  weakEncryption,
  comparePasswords,
  incrementCounter,
  divideNumbers,
  listBackups,
  deleteAccount,
  adminAction,
  setPassword,
  createConnection,
  getUserData,
  readBuffer,
  generateApiKey,
  login,
  authenticateUser,
  serveContent,
  checkCredentials,
  getAdminData,
  logMessage,
  elevatePrivileges,
  installPlugin,
  verifyUser
}
