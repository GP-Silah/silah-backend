module.exports = {
  setApiKey: jest.fn(),
  send: jest.fn().mockResolvedValue(true),
  MailService: jest.fn(),
};

