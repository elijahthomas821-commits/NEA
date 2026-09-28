"""All external data *in* — isolated behind marketplace-neutral interfaces.

Only code under ``app/collectors/<marketplace>/`` knows a marketplace's field names, condition
labels, size systems or URL formats. Everything else works with :class:`RawListing` and
:class:`RawSale`.

Listing intake is manual (you submit listings via Telegram, the API or CSV). No adapter here
fetches marketplace pages, APIs or images.
"""
