FROM public.ecr.aws/lts/ubuntu:24.04_stable

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /usr/bulldozer

RUN apt-get update && apt-get install -y python3 python3-pip mktorrent curl libwebp-dev libavif-dev ffmpeg && ln -s $(which python3) /usr/bin/python
 
RUN curl -fsSL https://deb.nodesource.com/setup_23.x -o nodesource_setup.sh && bash nodesource_setup.sh && apt-get install -y nodejs

RUN npm install -g podcast-dl

COPY ./ /usr/bulldozer

RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

CMD ["python", "bulldozer", "--check-config"]
