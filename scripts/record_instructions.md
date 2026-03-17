# Record the Hack Demo

## QuickTime Player

1. Open QuickTime Player.
2. Choose `File -> New Screen Recording`.
3. Select only the terminal window region.
4. Start recording.
5. Run:

   ```bash
   ./scripts/run_hack_demo.sh
   ```

6. Stop recording when the demo finishes.
7. Save the recording as:

   ```text
   docs/hack_demo.mov
   ```

## macOS CLI Alternative

Use the native screen recording tool:

```bash
screencapture -v docs/hack_demo.mov
```
