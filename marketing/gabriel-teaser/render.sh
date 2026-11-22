#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/assets build/scenes

copy_asset() {
  local source="$1"
  local dest="$2"
  test -f "$source"
  cp "$source" "$dest"
}

copy_asset "docs/assets/gabriel/screenshots/investigations.png" "build/assets/signin.png"
copy_asset "docs/assets/gabriel/screenshots/case-workspace.png" "build/assets/workspace.png"
copy_asset "docs/assets/gabriel/screenshots/specialist-assessments.png" "build/assets/specialists.png"
copy_asset "docs/assets/gabriel/screenshots/spending-controls.png" "build/assets/controls.png"
copy_asset "docs/assets/gabriel/screenshots/mobile-case.png" "build/assets/mobile.png"
copy_asset "docs/assets/gabriel/actions/preview-preflight.png" "build/assets/setup.png"

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
  -filter_complex "[0:a]volume=0.055,lowpass=f=180[a0];[1:a]volume=0.024,lowpass=f=600[a1];[2:a]volume=0.008,lowpass=f=1200[a2];[a0][a1][a2]amix=inputs=3:duration=longest,afade=t=in:st=0:d=1.5,afade=t=out:st=37:d=3,loudnorm=I=-24:TP=-2:LRA=7[a]" \
  -map "[a]" -c:a aac -b:a 192k build/score.m4a

ffmpeg -hide_banner -loglevel error -y -i build/video_silent.mp4 -i build/score.m4a \
  -map 0:v:0 -map 1:a:0 -c:v copy -c:a aac -b:a 192k -shortest -movflags +faststart \
  build/Gabriel_The_Defender_UI_Workflow_Teaser.mp4

ffprobe -v error -show_entries format=duration,size -of default=noprint_wrappers=1 build/Gabriel_The_Defender_UI_Workflow_Teaser.mp4
