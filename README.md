# Incident Agent — deployment guide

This is a **third, separate Render service**. It reuses:

- the same **Gemini API key**;
- the same **Neon database** (its own tables start with `inc_`).

---

## Step 1 — New GitHub repo

1. Go to https://github.com/new, name it `incident-agent`, and create it.
2. **Unzip `incident-agent.zip` first.**
3. Click **uploading an existing file** and drag in `app.py`, `requirements.txt`, `README.md` and `test_incident.py`. They must sit at the top level, not in a folder.
4. Click **Commit changes**.

## Step 2 — New Render web service

**New → Web Service →** pick `incident-agent`, then fill in:

| Setting | Value |
|---|---|
| Region | Singapore |
| Language | Python 3 |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn app:app --host 0.0.0.0 --port $PORT` |
| Instance Type | Free |

Add these environment variables:

| Name | Value |
|---|---|
| `GEMINI_API_KEY` | same key as before |
| `DATABASE_URL` | same Neon string as before |
| `PYTHON_VERSION` | `3.12.7` |

Click **Deploy Web Service** and wait for **Live**.

## Step 3 — Your base URL

Your base URL is the Render address, **with nothing after it**:

```
https://incident-agent-xxxx.onrender.com
```

Paste it into **"Deployed incident-agent base URL"**. The grader adds `/v2/incidents` itself.

Make sure it is the **incident-agent** address, not the mailroom one.

## Step 4 — Test before spending a Check

```
pip install requests
python test_incident.py https://incident-agent-xxxx.onrender.com
```

You want `0 failed`. The diagnoses should be `capacity_saturation` for the three checkout incidents and
`bad_deployment` for the payments one. The test uses 4 Gemini calls.

## Step 5 — Check

- **Wake the app first:** open the URL in your browser and wait for `ok`. Each request has only an
  18-second limit, and a sleeping free app takes longer than that to wake.
- Every run makes one fresh Gemini call, as the assignment requires. If Gemini is slow or fails,
  the agent reuses the plan it saved for the same incident on an earlier run.

## If the feedback shows problems

| Feedback | Try |
|---|---|
| Timeouts / transport deadline on create | Set `GEMINI_THINKING_BUDGET=0` (faster planning). |
| Diagnosis or action accuracy | Set `GEMINI_THINKING_BUDGET=1024`, only if timing is fine. |
| Gemini errors in Render **Logs** (`[gemini]` lines) | Set `GEMINI_MODEL` to a current model from https://ai.google.dev/gemini-api/docs/models |

After changing decision settings, you can clear saved plans in the Neon **SQL Editor**:
`DELETE FROM inc_plan_cache;`

## How it works

- **Planner:** one Gemini call per run. It receives the transcript, root causes, catalog and policy — never the `sensitive` object. Code then checks every choice: the root cause is from the allowed list, evidence IDs exist, there are at most 3 diagnostics, the effect comes from `effectTools`, and arguments fit the tool schema.
- **State machine:** receipts drive everything, with no model calls.
  - A 503 gets exactly one retry, using the same IDs and a new CLIENT span.
  - A timeout fails the run and suppresses the effect.
  - `rollback_deployment` and `disable_feature` are only sent after an approval receipt.
- **Trace:** built only from stored dispatches, receipts and timestamps, with the exact span names and counts the assignment specifies. Sensitive values and `doNotExport` strings are redacted from every response.
- **Replays:** return the stored JSON. Changed content returns 409, and a bad profile returns 400 and stores nothing.
