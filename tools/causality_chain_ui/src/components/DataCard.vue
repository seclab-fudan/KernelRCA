<script setup>
import { Handle, Position } from "@vue-flow/core";
import { ref, computed } from 'vue';
import eventBus from '@/utils/eventBus';
const props = defineProps({
  id: {
    type: String,
    required: true,
  },
  dataName: {
    type: String,
    required: true,
  },
  dataValue: {
    type: String,
    required: false,
    default: "",
  }
})
const valueText = `=${props.dataValue}`

const isHighlighted = ref(false);

const onNodeClick = () => {
  eventBus.emit('node-clicked', { type: 'dataItem', id: props.id });
};

eventBus.on('highlight-nodes', (highlightedNodes) => {
  let isHighlight = false;
  highlightedNodes.dataItemIds.forEach((dataID) => {
    if (Number(dataID) === Number(props.id)) {
      isHighlight = true;
    }
  })
  isHighlighted.value = isHighlight;
});

const databox = computed(() => {
  return isHighlighted.value ? 'highlightedData nodrag' : 'normalData nodrag';
});

const boxWidth = computed(() => {
  if (props.dataName.startsWith("[") || props.dataName.startsWith("0x")) {
    return '150px';
  }
  return '50px';
});

const showValue = ref(false);

const onMouseOver = () => {
  showValue.value = true;
};

const onMouseLeave = () => {
  showValue.value = false;
};

</script>

<template>
  <div :class="databox" :style="{ width: boxWidth }" @click="onNodeClick" @mouseover="onMouseOver"
    @mouseleave="onMouseLeave">
    <div class="data-content">
      <p class="data-name">{{ dataName }}</p>
    </div>
    <div class="data-anchor">
      <Handle id="bottomSource" :position="Position.Bottom" type="source" style="opacity: 0;top: 0" />
      <Handle id="rightSource" :position="Position.Right" type="source" style="opacity: 0;margin-top: 5px" />
      <Handle id="leftSource" :position="Position.Left" type="source" style="opacity: 0;margin-top: 5px" />

      <Handle id="topTarget" :position="Position.Top" type="target" style="opacity: 0;" />
      <Handle id="rightTarget" :position="Position.Right" type="target" style="opacity: 0;padding-left: 2px" />
      <Handle id="leftTarget" :position="Position.Left" type="target" style="opacity: 0;padding-right: 2px" />
    </div>
    <div v-show="showValue" class="value-text">
      <pre>{{ valueText }}</pre>
    </div>
  </div>
</template>


<style>
.highlightedData {
  position: relative;
  display: flex;
  flex-direction: column;
  border: 1px solid black;
  padding: 1px;
  font-family: Arial, sans-serif;
  justify-content: center;
  align-items: center;
  text-align: center;
  cursor: pointer;
  background-color: var(--active--color);
  height: 10px;
}

.normalData {
  position: relative;
  display: flex;
  flex-direction: column;
  border: 1px solid black;
  padding: 1px;
  background-color: white;
  font-family: Arial, sans-serif;
  justify-content: center;
  align-items: center;
  text-align: center;
  cursor: pointer;
  height: 10px;
}

.highlightedData:hover {
  background-color: var(--cover--bggcolor);
}

.normalData:hover {
  background-color: var(--cover--bggcolor);
}

.data-content {
  display: flex;
  padding: 1px;
}

.data-name {
  font-size: 10px;
  font-weight: bold;
  margin: 0;
  padding: 0 0 1px 0;
}

.data-anchor {
  width: 0;
  padding: 0;
}

.value-text {
  position: absolute;
  top: 100%;
  left: 50%;
  font-size: 10px;
  transform: translateX(-50%);
  background-color: #CD5C08;
  color: white;
  padding: 5px;
  border-radius: 4px;
  white-space: pre-wrap;
  z-index: 1000;
}
</style>