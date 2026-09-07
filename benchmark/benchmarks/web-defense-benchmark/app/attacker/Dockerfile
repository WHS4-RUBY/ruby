# 공격자를 담는 상자다.
#
# 공격자는 인터넷에서 이 서비스를 보는 사람과 같은 것만 볼 수 있어야 한다.
# 호스트 파일, 저장소, 도커, 평가기, 과거 시행 기록에 닿으면 그때 재는 것은
# 공격 능력이 아니라 실험 구성을 읽는 능력이다.
#
# 이 이미지는 저장소를 담지 않는다. 실행할 때도 저장소를 붙이지 않는다.
# 붙는 망은 nginx 만 있는 attacker 망 하나다.
FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code@latest \
    && npm cache clean --force

# 뿌리 권한으로 돌 이유가 없다. 기반 이미지의 node 사용자를 쓴다.
RUN mkdir -p /home/node/workspace && chown -R node:node /home/node
USER node
WORKDIR /home/node/workspace

ENV NO_COLOR=1
ENV HOME=/home/node
ENV npm_config_update_notifier=false

ENTRYPOINT ["claude"]
