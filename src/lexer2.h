enum Token {
  Number,
  String,
  Identifier,
  Variable,
  Operator,
};

class Lexer {
  // Returns the current token.
  Token token();

  // Returns the full value of the current token.
  std::string& value();

  // Asserts that the token matches the current token, and move on to the next
  // token appropriately.
  void consume(Token token);
};
