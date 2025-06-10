<template>
  <div>
    <div class="header">
      <p style="font-weight: bold;font-size: medium;height:10px">[BUG] {{ this.title }}</p>
      <p style="font-size:small;height:10px">This bug is reported by syzkaller at <a :href="this.report"
          target="_blank">{{
            this.report }}</a> </p>
      <p style="font-weight: bold;font-size: medium">Contextual Causality Chain</p>
    </div>
    <div style="height: 3vh">
      <el-row style="height: 100%">
        <div style="width: 24vw;height: 100%;text-align: left; display: flex;">
          <el-tag effect="dark" style="font-size: 15px;">Calling Context</el-tag>
          <ImageDialog :image-path="require('@/assets/helpcalltree.jpg')" />
        </div>
        <div style="width: 23vw;height: 100%;text-align: left; margin-left: 0.1vw; display: flex;">
          <el-tag effect="dark" style="font-size: 15px">Causality Chain</el-tag>
          <ImageDialog :image-path="require('@/assets/helpchain.jpg')" />
        </div>
        <div style="width: 23vw; height: 100%;text-align: left; margin-left: 0.1vw; display: flex;">
          <el-tag effect="dark" style="font-size: 15px">Data Dependency</el-tag>
          <ImageDialog :image-path="require('@/assets/helpdata.jpg')" />
        </div>
        <div style="width: 26vw;text-align: left; margin-left: 0.8vw; display: flex;">
          <el-tag effect="dark" style="font-size: 15px">Source Code</el-tag>
          <ImageDialog :image-path="require('@/assets/helpsource.jpg')" />
        </div>
      </el-row>
    </div>
    <el-row>
      <div class="layout-container-demo" style="height: 80vh; overflow: auto">
        <el-row class="container-border" style="height: 100%; overflow: auto">
          <div ref="calltree"
            style="width: 24vw;height: 100%; overflow-x: auto; overflow-y: hidden; scrollbar-gutter: stable;"
            @wheel="syncCCChainScrollWhell">
            <CallTree :nodes="treeNodes" :edges="treeEdges" />
          </div>
          <div ref="insview"
            style="width: 23vw;height: 100%; overflow-x: auto; overflow-y: hidden; scrollbar-gutter: stable;"
            class="border-left" @wheel="syncCCChainScrollWhell">
            <InsView :nodes="insNodes" :edges="insEdges"></InsView>
          </div>
          <div ref="dataview"
            style="width: 23vw; height: 100%; overflow-x: auto; overflow-y: auto; scrollbar-gutter: stable;"
            class="border-left" @scroll="syncCCChainScroll">
            <DataView :nodes="dataNodes" :edges="dataEdges"></DataView>
          </div>
        </el-row>
      </div>
      <el-scrollbar style="margin-left: 10px;border: 2px solid black;overflow-x: hidden">
        <el-container class="layout-container-demo" style="height: 80vh;width: 26vw;overflow-x: hidden">
          <CodeView v-if="sourceCodeArray !== []" :id="highlightedNodes.callNodeId" :code-items="sourceCodeArray">
          </CodeView>
        </el-container>
      </el-scrollbar>
    </el-row>
  </div>
</template>

<script>
import { nextTick, ref, setDevtoolsHook } from "vue";
import eventBus from '@/utils/eventBus';

import CallTree from '@/components/CallTree.vue'
import InsView from "@/components/InsView.vue";
import DataView from '@/components/DataView.vue'
import CodeView from "@/components/CodeView.vue"
import { MarkerType } from "@vue-flow/core";
import ImageDialog from "@/components/ImageDialog.vue";


export default {
  name: "HomeView",
  props: {
    id: {
      type: String,
      required: true
    }
  },
  components: {
    CallTree, InsView, DataView, CodeView, ImageDialog
  },
  setup() {
    let highlightedNodes = ref({
      callNodeId: null,
      insItemId: null,
      dataItemIds: [],
    });
    let sourceCodeArray = ref([]);
    return {
      highlightedNodes, sourceCodeArray
    }
  },
  data() {
    return {
      report: '',
      title: '',
      dataCards: null,
      rawCallData: {},
      rawInsData: {},
      rawData: {},
      rawChainData: {},
      defaultProps: {
        index: 'index',
        label: 'label',
        children: 'children'
      },
      treeNodes: [],
      treeEdges: [],
      insNodes: [],
      insEdges: [],
      insCounter: {},
      dataNodes: [],
      dataEdges: [],
    };
  },
  created() {
    this.loadData().then(this.show).then(() => {
      eventBus.on('node-clicked', ({ type, id }) => {
        const correspondingNodes = this.findCorrespondingNodes(type, id);
        this.highlightedNodes = correspondingNodes;
        eventBus.emit('highlight-nodes', this.highlightedNodes);
      });
    }
    );
  },
  methods: {
    show() {
      this.prepareInsTreeData();
      this.setDefaultScrollPosition();
      this.setDefaultHighlightedNodes();
    },
    setDefaultHighlightedNodes() {
      setTimeout(() => {
        if (Object.keys(this.rawInsData).length > 0) {
          const minInsNodeId = Object.keys(this.rawInsData).reduce((minId, key) => {
            return Number(key) < Number(minId) ? key : minId;
          });
          const crashNodes = this.findCorrespondingNodes('insItem', minInsNodeId);
          this.highlightedNodes = crashNodes;
          eventBus.emit('highlight-nodes', this.highlightedNodes);
        }
      });
    },
    setDefaultScrollPosition() {
      setTimeout(
        () => {
          const calltree = this.$refs.calltree;
          const insview = this.$refs.insview;
          const dataview = this.$refs.dataview;

          if (calltree) {
            calltree.scrollTop = calltree.scrollHeight;
            calltree.scrollLeft = calltree.scrollWidth;
          }
          if (insview) {
            insview.scrollTop = insview.scrollHeight;
          }
          if (dataview) {
            dataview.scrollTop = dataview.scrollHeight;
          }
        }
      )
    },
    syncCCChainScrollWhell(event) {
      const calltree = this.$refs.calltree;
      const dataview = this.$refs.dataview;
      const insview = this.$refs.insview;
      const deltaY = event.deltaY;

      requestAnimationFrame(() => {
        calltree.scrollTop += deltaY;
        dataview.scrollTop += deltaY;
        insview.scrollTop += deltaY;
      });
    },
    syncCCChainScroll(event) {
      const calltree = this.$refs.calltree;
      const insview = this.$refs.insview;

      const scrollTop = event.target.scrollTop;
      requestAnimationFrame(() => {
        calltree.scrollTop = scrollTop;
        insview.scrollTop = scrollTop;
      });
    },
    findCorrespondingNodes(type, id) {
      if (type === 'callNode') {
        this.sourceCodeArray = this.rawCallData[id].source_line;
        const insIdx = this.rawCallData[id].ins_idx;
        if (insIdx === 0) {
          return {
            callNodeId: Number(id),
            insItemId: null,
            dataItemIds: [],
          };
        } else {
          const dataArray = this.getDataArrayByInsIdx(insIdx);
          return {
            callNodeId: Number(id),
            insItemId: Number(insIdx),
            dataItemIds: dataArray,
          };
        }
      } else if (type === 'insItem') {
        const callIdx = this.rawInsData[id].call_idx;
        this.sourceCodeArray = this.rawCallData[callIdx].source_line;
        const dataArray = this.getDataArrayByInsIdx(id);
        return {
          callNodeId: Number(callIdx),
          insItemId: Number(id),
          dataItemIds: dataArray,
        };
      } else if (type === 'dataItem') {
        const insIdx = this.rawData[id].ins_idx
        const dataArray = this.getDataArrayByInsIdx(insIdx);
        const callIdx = this.rawInsData[insIdx].call_idx;
        this.sourceCodeArray = this.rawCallData[callIdx].source_line;
        return {
          callNodeId: Number(callIdx),
          insItemId: Number(insIdx),
          dataItemIds: dataArray,
        };
      }
      return {
        callNodeId: null,
        insItemId: null,
        dataItemIds: [],
      };
    },
    isRegister(dataName) {
      return !(dataName && (dataName.startsWith('0x') || dataName.startsWith('[')));
    },
    getDataArrayByInsIdx(insIdx) {
      const newDataIdx = [];
      for (const key in this.rawData) {
        const dataItem = this.rawData[key];
        if (dataItem.ins_idx === Number(insIdx)) {
          newDataIdx.push(key);
        }
      }
      return newDataIdx;
    },
    isNeighborNode(sourceInsIndex, targetInsIndex) {
      const sourceCount = this.insCounter[sourceInsIndex];
      const targetCount = this.insCounter[targetInsIndex];
      const result = (sourceCount + 1) === targetCount || (sourceCount - 1) === targetCount
      return result;
    },
    prepareInsTreeData() {
      const insnodes = {};
      const _insnodes = [];
      const insedges = [];
      const insheights = {};

      const marginForLeftArrow = 20;
      for (const key in this.rawInsData) {
        const item = this.rawInsData[key];
        const name = item.name;
        const desc = item.desc;
        let n_desc_lines = 0;
        if (desc !== '') {
          n_desc_lines = desc.split('\n').length;
        }

        const nameHeight = 15;
        const descHeight = n_desc_lines * 15;
        const margin = 30 * 2; /* top arrow margin + bottom arrow margin */
        insheights[key] = nameHeight + descHeight + margin;

        insnodes[key] = {
          id: key,
          type: 'ins-item',
          position: { x: marginForLeftArrow, y: 0, height: insheights[key] },
          data: {
            insName: item.name,
            insDesc: item.desc
          }
        };
      }

      // prepare tree
      const treenodes = {};
      const _treenodes = [];
      const treeedges = [];
      const nodeDepths = {};

      for (const key in this.rawCallData) {
        const item = this.rawCallData[key];
        treenodes[key] = {
          id: key,
          type: 'callnode',
          position: { x: 0, y: 0, height: 0 },
          data: {
            callName: item.name,
          }
        };
      }

      const calculateDepth = (nodeId) => {
        if (nodeDepths[nodeId] !== undefined) {
          return nodeDepths[nodeId];
        }
        const item = this.rawCallData[nodeId];
        const parentIdx = item.parent_idx;

        if (parentIdx === 0) {
          nodeDepths[nodeId] = 0;
        } else {
          nodeDepths[nodeId] = calculateDepth(parentIdx) + 1;
        }
        return nodeDepths[nodeId];
      }

      const indentWidth = 32;
      for (const key in treenodes) {
        const depth = calculateDepth(key);
        treenodes[key].position.x = depth * indentWidth;
      }

      for (const idx in this.rawCallData) {
        const item = this.rawCallData[idx];
        const parentIdx = item.parent_idx;
        if (parentIdx !== 0) {
          treeedges.push({
            id: 'e' + parentIdx + '->' + idx,
            source: `${parentIdx}`,
            target: idx,
            type: 'smoothstep',
            style: { stroke: "#664343" },
          })
        }
      }

      const minimalMargin = 32;
      var lastY = 0;
      for (const key in treenodes) {
        const tree = treenodes[key];
        const insid = this.rawCallData[key].ins_idx;
        tree.position.y = lastY;
        if (insid === 0) {
          tree.position.height = minimalMargin;
          lastY = lastY + minimalMargin;
        }
        else {
          tree.position.height = insheights[insid];
          insnodes[insid].position.y = lastY;
          lastY = lastY + insheights[insid];
        }
      }

      let count = 0;

      Object.keys(this.rawInsData)
        .sort((a, b) => insnodes[a].position.y - insnodes[b].position.y)
        .forEach((key) => {
          this.insCounter[key] = count;
          count++;
        });

      let rightArray = Array.from({ length: Object.keys(this.rawInsData).length }, () => false);
      let leftArray = Array.from({ length: Object.keys(this.rawInsData).length }, () => false);

      for (const key in this.rawChainData) {
        this.rawChainData[key].forEach((sourceItem) => {
          let defaultSourceHandle = 'bottomSource';
          let defaultTargetHandle = 'topTarget';
          if (this.isNeighborNode(sourceItem, key)) {
            // straight line for neighbor nodes
          } else {
            // not neighbor nodes
            const sourceCount = this.insCounter[sourceItem];
            const targetCount = this.insCounter[key];

            if (rightArray[sourceCount] === true || rightArray[targetCount] === true) {
              // connect left side
              defaultSourceHandle = 'leftSource';
              defaultTargetHandle = 'leftTarget';
              // occupy position from sourceCount+1 to targetCount-1
              leftArray.fill(true, sourceCount + 1, targetCount);
            } else {
              // connect right side
              defaultSourceHandle = 'rightSource';
              defaultTargetHandle = 'rightTarget';
              // occupy position from sourceCount+1 to targetCount-1
              rightArray.fill(true, sourceCount + 1, targetCount);
            }
          }
          insedges.push(
            {
              id: 'e' + sourceItem + '->' + key,
              source: `${sourceItem}`,
              target: key,
              type: 'default',
              style: { strokeWidth: '2px', strokeLinecap: 'round' },
              pathOptions: { curvature: 2 },
              sourceHandle: defaultSourceHandle,
              targetHandle: defaultTargetHandle,
              markerEnd: MarkerType.ArrowClosed,
            }
          )
        })
      }

      // prepare data
      const datanodes = {};
      const _datanodes = [];
      const dataedges = [];
      this.dataCards = new Map();
      let rightDataArray = Array.from({ length: Object.keys(this.rawInsData).length }, () => false);
      let leftDataArray = Array.from({ length: Object.keys(this.rawInsData).length }, () => false);


      for (const key in this.rawData) {
        const dataItem = this.rawData[key];
        const insIndex = dataItem.ins_idx;

        const sourcesDataArray = dataItem.sources;

        sourcesDataArray.forEach((sourceDataItem) => {
          const sourceInsIndex = this.rawData[sourceDataItem].ins_idx;
          const sourceInsItem = this.rawInsData[sourceInsIndex];

          let defaultSourceHandle = 'bottomSource';
          let defaultTargetHandle = 'topTarget';
          let defaultEdgeType = 'smoothstep'

          if (this.isNeighborNode(sourceInsIndex, insIndex)) {
            defaultEdgeType = 'straight'
          } else {
            const sourceInsInputs = sourceInsItem.inputs;
            if (Number(sourceDataItem) === sourceInsInputs[0]) {
              defaultSourceHandle = 'leftSource';
              defaultTargetHandle = 'leftTarget';
            } else {
              defaultSourceHandle = 'rightSource';
              defaultTargetHandle = 'rightTarget';
            }
          }
          dataedges.push(
            {
              id: 'e' + key + '->' + sourceDataItem,
              source: key,
              target: `${sourceDataItem}`,
              type: defaultEdgeType,
              style: { strokeWidth: 2, strokeLinecap: 'round' },
              pathOptions: { curvature: 3 },
              sourceHandle: defaultSourceHandle,
              targetHandle: defaultTargetHandle,
              markerEnd: { type: MarkerType.ArrowClosed, width: 10, height: 10 },
            }
          )

        })

        const insIdx = dataItem.ins_idx;
        const insY = insnodes[insIdx].position.y;
        const insH = insnodes[insIdx].position.height;

        if (this.getDataCardType(Number(key)) === 'output') {
          datanodes[key] = {
            id: key,
            type: 'data-item',
            position: { x: 40, y: insY + 40, height: insH },
            data: {
              dataName: dataItem.name,
              dataValue: dataItem.value,
              isInput: false,
            },
          }
          _datanodes.push(datanodes[key]);
        } else {
          if (!this.dataCards.has(insIdx)) {
            this.dataCards.set(insIdx, []);
            datanodes[key] = {
              id: key,
              type: 'data-item',
              position: { x: 40, y: insY, height: insH },
              data: {
                dataName: dataItem.name,
                dataValue: dataItem.value,
                isInput: true,
              },
            }
            let rowArray = this.dataCards.get(insIdx);
            rowArray.push(datanodes[key]);
            _datanodes.push(datanodes[key]);
          }
          else {
            let rowArray = this.dataCards.get(insIdx);
            const lastItem = rowArray[rowArray.length - 1];
            const lastNodeX = lastItem.position.x;
            const lastNodeWidth = this.isRegister(lastItem.data.dataName) ? 50 : 150;
            const spaceWidth = 20;
            datanodes[key] = {
              id: key,
              type: 'data-item',
              position: { x: lastNodeX + lastNodeWidth + spaceWidth, y: insY, height: insH },
              data: {
                dataName: dataItem.name,
                dataValue: dataItem.value,
                isInput: true,
              }
            }
            rowArray.push(datanodes[key]);
            _datanodes.push(datanodes[key]);
          }
        }

      }

      for (const insIdx in this.rawInsData) {
        const inputArray = this.rawInsData[insIdx].inputs;
        const outputIdx = this.rawInsData[insIdx].outputs[0];
        for (const index in inputArray) {
          const inputIdx = String(inputArray[index]);
          dataedges.push({
            id: 'e' + inputIdx + '->' + outputIdx,
            source: `${inputIdx}`,
            target: String(outputIdx),
            type: 'straight',
            style: { strokeWidth: 2, strokeLinecap: 'round' },
            pathOptions: { curvature: 3 },
            markerEnd: { type: MarkerType.ArrowClosed, width: 10, height: 10 },
            sourceHandle: 'bottomSource',
            targetHandle: 'topTarget',
          })
        }
      }

      this.dataEdges = dataedges;
      this.dataNodes = _datanodes;

      for (const key in treenodes) {
        _treenodes.push(treenodes[key]);
      }
      this.treeNodes = _treenodes;
      this.treeEdges = treeedges;

      for (const key in insnodes) {
        _insnodes.push(insnodes[key]);
      }
      this.insNodes = _insnodes;
      this.insEdges = insedges;
    },
    getDataCardType(dataIndex) {
      const dataItem = this.rawData[dataIndex];
      const insItem = this.rawInsData[dataItem.ins_idx];
      for (const index in insItem.inputs) {
        if (dataIndex === insItem.inputs[index]) {
          return 'input';
        }
      }
      return 'output';
    },
    async loadData() {
      try {
        const flist = await fetch('/report-list.json');
        const reportFiles = await flist.json();
        const filePath = reportFiles.find(file => file.startsWith(`crash_${this.id}`));

        const response = await fetch("/" + filePath);
        const jsonData = await response.json();
        this.rawCallData = jsonData.call;
        this.rawInsData = jsonData.ins;
        this.rawData = jsonData.data;
        this.rawChainData = jsonData.chain;
        this.report = jsonData.report;
        this.title = jsonData.title;
      } catch (error) {
        console.error("RCA Report Load Fail:", this.id);
      }
    },
    buttonEmits() {
      this.showSourceCode(1988);
    }
  },
}
</script>

<style scoped>
.image-container {
  position: relative;
  height: 100%;
  display: flex;
  justify-content: center;
  align-items: center;
}

::v-deep .hljs-ln-numbers {
  text-align: center;
  color: black;
  border-right: 1px solid black;
  vertical-align: top;
  padding-right: 5px !important;
}

::v-deep .hljs-ln-code {
  padding-left: 5px !important;
}

.header {
  text-align: left;
}

.container-border {
  border: 2px solid black;
  height: 100%;
}

.layout-container-demo {
  display: flex;
}

.border-left {
  border-left: 2px solid black;
}
</style>
