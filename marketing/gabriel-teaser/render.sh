#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/assets build/scenes

download() {
  local url="$1"
  local dest="$2"
  curl --fail --location --retry 3 --retry-delay 2 "$url" --output "$dest"
}

download "https://sdmntprwestus3.oaiusercontent.com/files/00000000-4474-81fd-96d4-62396a749777/raw?se=2026-11-16T23%3A53%3A31Z&sp=r&sv=2026-06-06&sr=b&scid=01a1e68f-88f5-74b1-a582-cdbd6da519ee&skoid=434ec24f-a0f0-4e64-b0de-2e2053f69735&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2026-11-16T16%3A22%3A06Z&ske=2026-11-17T16%3A22%3A06Z&sks=b&skv=2026-06-06&sig=Hz/u7yA4odR4a%2B0UR8GMvGLfjNzOQdatv5HudVRyIGs%3D" "build/assets/signin.png"
download "https://sdmntprwestus3.oaiusercontent.com/files/00000000-e094-81fd-9844-51eaa2d1d86b/raw?se=2026-11-16T23%3A53%3A31Z&sp=r&sv=2026-06-06&sr=b&scid=01a1e68f-88f5-74b1-a582-cdbd6da519ee&skoid=434ec24f-a0f0-4e64-b0de-2e2053f69735&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2026-11-16T14%3A30%3A37Z&ske=2026-11-17T14%3A30%3A37Z&sks=b&skv=2026-06-06&sig=nautDGHygheRnx03JSwKSTSd0mNaPwKMSqwR%2B/GcT%2Bg%3D" "build/assets/workspace.png"
download "https://sdmntprwestus.oaiusercontent.com/files/00000000-b8d0-8230-8d7b-00176b1f9b45/raw?se=2026-11-16T23%3A53%3A31Z&sp=r&sv=2026-06-06&sr=b&scid=01a1e68f-88f5-74b1-a582-cdbd6da519ee&skoid=434ec24f-a0f0-4e64-b0de-2e2053f69735&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2026-11-16T14%3A48%3A16Z&ske=2026-11-17T14%3A48%3A16Z&sks=b&skv=2026-06-06&sig=Ams1w4iwv7IMFe90tlqU86MI4smp1VddY0bOU%2BSjx5Y%3D" "build/assets/specialists.png"
download "https://sdmntprcentralus.oaiusercontent.com/files/00000000-c668-81f5-9726-52539d368f40/raw?se=2026-11-16T23%3A53%3A31Z&sp=r&sv=2026-06-06&sr=b&scid=01a1e68f-88f5-74b1-a582-cdbd6da519ee&skoid=434ec24f-a0f0-4e64-b0de-2e2053f69735&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2026-11-16T14%3A52%3A53Z&ske=2026-11-17T14%3A52%3A53Z&sks=b&skv=2026-06-06&sig=yW1LOtN3%2B9PKA0zCpMFpMj8y1pFq7kSS33SAG/Qs7mo%3D" "build/assets/controls.png"
download "https://sdmntprwestus3.oaiusercontent.com/files/00000000-02dc-81fd-ab03-80de8aab9ec7/raw?se=2026-11-16T23%3A53%3A31Z&sp=r&sv=2026-06-06&sr=b&scid=01a1e68f-88f5-74b1-a582-cdbd6da519ee&skoid=434ec24f-a0f0-4e64-b0de-2e2053f69735&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2026-11-16T14%3A38%3A24Z&ske=2026-11-17T14%3A38%3A24Z&sks=b&skv=2026-06-06&sig=9iBRsWYePRPHY4XMruOw%2BfhaOXXogz00bXDx6zYwwqI%3D" "build/assets/mobile.png"
download "https://sdmntpreastus3.oaiusercontent.com/files/00000000-981c-8212-bb40-c84baae3b562/raw?se=2026-11-16T23%3A53%3A31Z&sp=r&sv=2026-06-06&sr=b&scid=01a1e68f-88f5-74b1-a582-cdbd6da519ee&skoid=434ec24f-a0f0-4e64-b0de-2e2053f69735&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2026-11-16T13%3A47%3A09Z&ske=2026-11-17T13%3A47%3A09Z&sks=b&skv=2026-06-06&sig=uW5gjj6SAM/4%2BlYiqy29uhJh9YZyMb3cs3CRKruAYPk%3D" "build/assets/setup.png"

FONT="/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

make_scene() {
  local index="$1"
  local image="$2"
  local headline="$3"
  local subline="$4"
  local direction="$5"
  local pan_x

  if [[ "$direction" == "left" ]]; then
    pan_x="(iw-iw/zoom)*(1-on/150)"
  elif [[ "$direction" == "right" ]]; then
    pan_x="(iw-iw/zoom)*(on/150)"
  else
    pan_x="iw/2-(iw/zoom/2)"
  fi

  ffmpeg -hide_banner -loglevel error -y -loop 1 -framerate 30 -i "$image" \
    -vf "scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color=0x050811,zoompan=z='min(zoom+0.0004,1.06)':x='$pan_x':y='ih/2-(ih/zoom/2)':d=150:s=1920x1080:fps=30,drawbox=x=0:y=0:w=iw:h=92:color=0x050811@0.80:t=fill,drawtext=fontfile=$FONT_BOLD:text='GABRIEL — THE DEFENDER':fontcolor=0xF5F7FA:fontsize=34:x=64:y=27,drawbox=x=0:y=790:w=iw:h=290:color=0x050811@0.78:t=fill,drawtext=fontfile=$FONT_BOLD:text='$headline':fontcolor=white:fontsize=62:x=(w-text_w)/2:y=850,drawtext=fontfile=$FONT:text='$subline':fontcolor=0xA7D8D1:fontsize=34:x=(w-text_w)/2:y=940,fade=t=in:st=0:d=0.25,fade=t=out:st=4.75:d=0.25,format=yuv420p" \
    -t 5 -r 30 -an -c:v libx264 -preset medium -crf 18 "build/scenes/scene_${index}.mp4"
}

make_scene "01" "build/assets/signin.png" "One analyst. Too many signals." "Meet the defensive assistant built for the work." "center"
make_scene "02" "build/assets/signin.png" "Secure by design." "Analyst identity and authorization come first." "right"
make_scene "03" "build/assets/setup.png" "Point Gabriel to the console." "Vendor-neutral orientation before investigation." "left"
make_scene "04" "build/assets/workspace.png" "Observe. Correlate. Verify." "Evidence, timeline, and case reasoning stay together." "right"
make_scene "05" "build/assets/specialists.png" "12 specialists. 240 role-bound skills." "Grounded capabilities, orchestrated around the case." "left"
make_scene "06" "build/assets/controls.png" "Bounded access. Controlled spend." "Keys, limits, and safeguards remain visible." "right"
make_scene "07" "build/assets/workspace.png" "No final action without the analyst." "Gabriel investigates. The analyst decides." "left"
make_scene "08" "build/assets/mobile.png" "Stay with the case." "Open source — coming soon." "center"

cat > build/scenes.txt <<'EOF'
file 'scenes/scene_01.mp4'
file 'scenes/scene_02.mp4'
file 'scenes/scene_03.mp4'
file 'scenes/scene_04.mp4'
file 'scenes/scene_05.mp4'
file 'scenes/scene_06.mp4'
file 'scenes/scene_07.mp4'
file 'scenes/scene_08.mp4'
EOF

ffmpeg -hide_banner -loglevel error -y -f concat -safe 0 -i build/scenes.txt -c copy build/video_silent.mp4

ffmpeg -hide_banner -loglevel error -y \
  -f lavfi -i "sine=frequency=55:sample_rate=48000:duration=40" \
  -f lavfi -i "sine=frequency=110:sample_rate=48000:duration=40" \
  -f lavfi -i "anoisesrc=color=pink:sample_rate=48000:duration=40" \
  -filter_complex "[0:a]volume=0.055,lowpass=f=180[a0];[1:a]volume='0.018+0.010*sin(2*PI*t/5)',lowpass=f=600[a1];[2:a]volume=0.008,lowpass=f=1200[a2];[a0][a1][a2]amix=inputs=3:duration=longest,afade=t=in:st=0:d=1.5,afade=t=out:st=37:d=3,loudnorm=I=-24:TP=-2:LRA=7[a]" \
  -map "[a]" -c:a aac -b:a 192k build/score.m4a

ffmpeg -hide_banner -loglevel error -y -i build/video_silent.mp4 -i build/score.m4a \
  -map 0:v:0 -map 1:a:0 -c:v copy -c:a aac -b:a 192k -shortest -movflags +faststart \
  build/Gabriel_The_Defender_UI_Workflow_Teaser.mp4

ffprobe -v error -show_entries format=duration,size -of default=noprint_wrappers=1 build/Gabriel_The_Defender_UI_Workflow_Teaser.mp4
