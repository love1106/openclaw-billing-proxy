FROM node:20-alpine

# Claude Code CLI — needed by the in-process refresher to rotate ~/.claude/.credentials.json
RUN npm install -g @anthropic-ai/claude-code

WORKDIR /app
COPY proxy.js ./

EXPOSE 18801

# Credentials are expected at /root/.claude/.credentials.json
# Mount with: -v $HOME/.claude:/root/.claude
CMD ["node", "proxy.js", "--host", "0.0.0.0"]
