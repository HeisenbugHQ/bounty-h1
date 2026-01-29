# Surface Detector v1

Run manually for a program:

```bash
PROGRAM_HANDLE=bitmex python workers/analysis/surface_detector_v1.py
```

This uses only existing DB data (url_observations, param_observations, latest HTTP) and upserts into `surface_findings`.
